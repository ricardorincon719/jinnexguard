"""Lo que se publica en npm y PyPI: metadatos, artefactos y procedencia.

El paquete que se instala no tiene por qué salir del repo que muestra su página:
quien publica sube lo que quiere (xz-utils escondió su puerta trasera en el
tarball del release, no en git). Acá se resuelve qué versión se publicó, de qué
repo dice venir, y se bajan sus artefactos como DATOS: se verifica el hash del
registro y se extraen a mano, sin `npm install`, sin `pip install`, sin correr
setup.py. Rutas absolutas, `..`, enlaces y dispositivos se descartan.

Solo stdlib, igual que el resto del motor.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import tarfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI = "https://pypi.org"
TIMEOUT = 20
MAX_DOWNLOAD_BYTES = 100_000_000    # un artefacto más grande no se baja
MAX_EXTRACTED_BYTES = 300_000_000   # tope contra bombas de compresión
MAX_MEMBERS = 30_000
_CHUNK = 1 << 16

# Hosts de los que sabemos clonar (los mismos que acepta fetch.normalize_url).
_REPO_HOSTS = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org")
_REPO_URL = re.compile(
    r"(?:git\+)?(?:https?|git|ssh|git\+ssh)://(?:[^@/]+@)?(?:www\.)?"
    r"(?P<host>[\w.-]+)[:/](?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?"
    r"(?:/(?:tree|blob|-/tree)/[^/]+(?P<dir>(?:/[^#?]+)?))?/?(?:[#?].*)?$")
_SCP_URL = re.compile(r"^(?:[\w.-]+@)(?P<host>[\w.-]+):(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")
_SHORTHAND = re.compile(r"^(?:(?P<host>github|gitlab|bitbucket):)?(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.IGNORECASE)
_PYPI_NAME = re.compile(r"^[A-Za-z0-9][\w.-]*$")
_VERSION = re.compile(r"^[\w.+!-]+$")


class RegistryError(Exception):
    """No se pudo resolver o bajar un paquete (no existe, red, hash que no coincide…)."""


@dataclass(frozen=True)
class PackageSpec:
    ecosystem: str            # "npm" | "pypi"
    name: str
    version: str | None = None   # None = la última publicada

    @property
    def label(self) -> str:
        sep = "==" if self.ecosystem == "pypi" else "@"
        return f"{self.ecosystem}:{self.name}" + (f"{sep}{self.version}" if self.version else "")


@dataclass(frozen=True)
class Artifact:
    kind: str                 # "npm" | "sdist" | "wheel"
    filename: str
    url: str
    digest: tuple[str, str]   # (algoritmo de hashlib, valor esperado en hex)
    size: int | None = None

    @property
    def label(self) -> str:
        return f"{'npm' if self.kind == 'npm' else 'pypi'}:{self.filename}"


@dataclass
class Release:
    """Una versión publicada: qué se baja y de qué repo dice venir."""

    spec: PackageSpec                       # con la versión ya resuelta
    artifacts: list[Artifact]
    repo_url: str | None = None             # https://host/owner/repo, declarado por quien publica
    repo_dir: str = ""                      # subcarpeta del repo (monorepos)
    ref_hints: list[str] = field(default_factory=list)   # commit/tags que podrían ser esta versión
    published_at: str | None = None
    provenance: dict | None = None          # lo que declara la atestación del registro
    other_wheels: int = 0                   # wheels de otras plataformas que no se bajaron


# --- nombres y URLs ---------------------------------------------------------

def parse_spec(target: str) -> PackageSpec | None:
    """`npm:nombre[@versión]` o `pypi:nombre[==versión]`; None si no es un paquete."""
    value = target.strip()
    if value.startswith("npm:"):
        rest = value[4:]
        name, _, version = rest.rpartition("@") if rest.rfind("@") > 0 else (rest, "", "")
        if _NPM_NAME.match(name) and (not version or _VERSION.match(version)):
            return PackageSpec("npm", name, version or None)
        raise RegistryError(f"Invalid npm package name: {rest}")
    if value.startswith("pypi:"):
        name, _, version = value[5:].partition("==")
        if _PYPI_NAME.match(name) and (not version or _VERSION.match(version)):
            return PackageSpec("pypi", name, version or None)
        raise RegistryError(f"Invalid PyPI package name: {value[5:]}")
    return None


def normalize_repo(raw: str | None) -> tuple[str, str] | None:
    """(https://host/owner/repo, subcarpeta) de una URL de repo como la escriben los manifiestos."""
    if not raw or not isinstance(raw, str):
        return None
    value = raw.strip()
    subdir = ""
    match = _REPO_URL.match(value) or _SCP_URL.match(value)
    if match:
        host = match.group("host").lower().removeprefix("www.")
        subdir = (match.groupdict().get("dir") or "").strip("/")
    else:
        match = _SHORTHAND.match(value)   # npm: "owner/repo" o "github:owner/repo"
        if not match:
            return None
        host = f"{match.group('host') or 'github'}.com"
        if host == "bitbucket.com":
            host = "bitbucket.org"
    if host not in _REPO_HOSTS:
        return None
    repo = match.group("repo").removesuffix(".git")
    return f"https://{host}/{match.group('owner')}/{repo}", subdir


def same_repo(a: str | None, b: str | None) -> bool:
    left, right = normalize_repo(a), normalize_repo(b)
    return bool(left and right and left[0].lower() == right[0].lower())


def tag_candidates(name: str, version: str) -> list[str]:
    """Las formas habituales de etiquetar una versión en git."""
    short = name.rsplit("/", 1)[-1]
    return list(dict.fromkeys([f"v{version}", version, f"{name}@{version}",
                               f"{short}@{version}", f"{short}-{version}", f"{short}-v{version}"]))


# --- HTTP -------------------------------------------------------------------

def _request(url: str, accept: str = "application/json") -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": "JinnexGuard", "Accept": accept})


def _get_json(url: str, *, accept: str = "application/json") -> dict | None:
    """El JSON de `url`, o None si el registro dice 404."""
    try:
        with urllib.request.urlopen(_request(url, accept), timeout=TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RegistryError(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RegistryError(f"{url}: {exc}") from exc


def download(artifact: Artifact, destination: Path) -> Path:
    """Baja el artefacto y verifica el hash que publica el registro. Nunca lo ejecuta."""
    if artifact.size and artifact.size > MAX_DOWNLOAD_BYTES:
        raise RegistryError(f"{artifact.filename} is {artifact.size} bytes; not downloading it.")
    if not artifact.url.startswith("https://"):
        raise RegistryError(f"Download URL is not https: {artifact.url}")
    algorithm, expected = artifact.digest
    digest = hashlib.new(algorithm)
    target = destination / PurePosixPath(artifact.filename).name
    total = 0
    try:
        with urllib.request.urlopen(_request(artifact.url, "*/*"), timeout=TIMEOUT) as response, \
                open(target, "wb") as out:
            while chunk := response.read(_CHUNK):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise RegistryError(f"{artifact.filename} exceeds {MAX_DOWNLOAD_BYTES} bytes.")
                digest.update(chunk)
                out.write(chunk)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RegistryError(f"Could not download {artifact.filename}: {exc}") from exc
    if digest.hexdigest() != expected.lower():
        raise RegistryError(f"The hash of {artifact.filename} does not match the registry's.")
    return target


# --- extracción segura ------------------------------------------------------

def _safe_member(name: str) -> PurePosixPath | None:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return path


def _write_member(source, destination: Path, budget: list[int]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "wb") as out:
        while chunk := source.read(_CHUNK):
            budget[0] -= len(chunk)
            if budget[0] < 0:
                raise RegistryError("The decompressed artifact exceeds the limit; possible decompression bomb.")
            out.write(chunk)


def extract(archive: Path, destination: Path) -> Path:
    """Extrae un .tgz/.tar.gz/.zip/.whl solo con archivos regulares y devuelve la raíz del paquete.

    La raíz es la carpeta única de arriba si la hay (`package/` en npm,
    `nombre-1.0/` en un sdist); un wheel no tiene y se usa la carpeta entera.
    """
    destination.mkdir(parents=True, exist_ok=True)
    budget = [MAX_EXTRACTED_BYTES]
    count = 0
    if archive.suffix in (".zip", ".whl"):
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                is_link = (info.external_attr >> 16) & 0o170000 == 0o120000
                path = _safe_member(info.filename)
                if info.is_dir() or is_link or path is None:
                    continue
                count += 1
                if count > MAX_MEMBERS:
                    raise RegistryError("The artifact has too many files.")
                with bundle.open(info) as source:
                    _write_member(source, destination.joinpath(*path.parts), budget)
    else:
        with tarfile.open(archive, "r:*") as bundle:
            for member in bundle:
                path = _safe_member(member.name)
                if not member.isreg() or path is None:   # enlaces, dispositivos, carpetas
                    continue
                count += 1
                if count > MAX_MEMBERS:
                    raise RegistryError("The artifact has too many files.")
                source = bundle.extractfile(member)
                if source is not None:
                    _write_member(source, destination.joinpath(*path.parts), budget)
    entries = list(destination.iterdir())
    if archive.suffix != ".whl" and len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return destination


# --- npm --------------------------------------------------------------------

def _slsa_claims(predicate: dict) -> dict:
    """Repo, commit y workflow de una procedencia SLSA (v1 o v0.2)."""
    build = predicate.get("buildDefinition") or {}
    workflow = (build.get("externalParameters") or {}).get("workflow") or {}
    claims = {"repository": workflow.get("repository"), "ref": workflow.get("ref"),
              "workflow": workflow.get("path")}
    for dependency in build.get("resolvedDependencies") or []:
        commit = (dependency.get("digest") or {}).get("gitCommit")
        if commit:
            claims["commit"] = commit
            break
    if not claims["repository"]:   # SLSA v0.2
        source = (predicate.get("invocation") or {}).get("configSource") or {}
        uri, _, ref = (source.get("uri") or "").partition("@")
        claims.update(repository=uri.removeprefix("git+") or None, ref=ref or None,
                      workflow=source.get("entryPoint"),
                      commit=(source.get("digest") or {}).get("sha1"))
    return {key: value for key, value in claims.items() if value}


def _npm_provenance(version_doc: dict) -> dict | None:
    url = ((version_doc.get("dist") or {}).get("attestations") or {}).get("url")
    if not url or not url.startswith(NPM_REGISTRY):
        return None
    data = _get_json(url) or {}
    for item in data.get("attestations") or []:
        if "slsa.dev/provenance" not in (item.get("predicateType") or ""):
            continue
        payload = ((item.get("bundle") or {}).get("dsseEnvelope") or {}).get("payload")
        if not payload:
            continue
        statement = json.loads(base64.b64decode(payload))
        claims = _slsa_claims(statement.get("predicate") or {})
        if claims:
            return {**claims, "source": "npm (SLSA)"}
    return None


def _resolve_npm(spec: PackageSpec) -> Release:
    encoded = spec.name.replace("/", "%2F")
    doc = _get_json(f"{NPM_REGISTRY}/{encoded}/{urllib.parse.quote(spec.version or 'latest')}")
    if doc is None:
        raise RegistryError(f"{spec.label} does not exist on npm.")
    version = doc.get("version") or spec.version or "?"
    dist = doc.get("dist") or {}
    integrity = dist.get("integrity") or ""
    if integrity.startswith("sha512-"):
        digest = ("sha512", base64.b64decode(integrity[7:]).hex())
    elif dist.get("shasum"):
        digest = ("sha1", dist["shasum"])
    else:
        raise RegistryError(f"{spec.label}: the registry publishes no hash for the tarball.")
    tarball = dist.get("tarball") or ""
    artifact = Artifact("npm", f"{spec.name}@{version}.tgz".replace("/", "__"), tarball, digest)
    repository = doc.get("repository")
    raw_repo = repository.get("url") if isinstance(repository, dict) else repository
    repo = normalize_repo(raw_repo)
    subdir = (repository.get("directory") or "") if isinstance(repository, dict) else ""
    release = Release(
        PackageSpec("npm", spec.name, version), [artifact],
        repo_url=repo[0] if repo else None,
        repo_dir=(subdir or (repo[1] if repo else "")).strip("/"),
        ref_hints=[doc["gitHead"]] if doc.get("gitHead") else [])
    release.provenance = _npm_provenance(doc)
    return release


# --- PyPI -------------------------------------------------------------------

def _der_length(data: bytes, index: int) -> tuple[int, int]:
    first = data[index]
    if first < 0x80:
        return first, index + 1
    width = first & 0x7F
    return int.from_bytes(data[index + 1:index + 1 + width], "big"), index + 1 + width


def _oid(dotted: str) -> bytes:
    numbers = [int(n) for n in dotted.split(".")]
    body = bytearray([40 * numbers[0] + numbers[1]])
    for number in numbers[2:]:
        chunk = [number & 0x7F]
        while number := number >> 7:
            chunk.append(0x80 | (number & 0x7F))
        body += bytes(reversed(chunk))
    return bytes([0x06, len(body)]) + bytes(body)


# Extensiones del certificado de Sigstore (Fulcio) con el commit y el ref del build.
_FULCIO_DIGEST = _oid("1.3.6.1.4.1.57264.1.13")
_FULCIO_REF = _oid("1.3.6.1.4.1.57264.1.14")


def _cert_extension(der: bytes, oid: bytes) -> str | None:
    """Lee una extensión de texto de un certificado DER sin librerías de X.509.

    Solo se usa para mostrar qué commit DECLARA el certificado; la firma no se
    verifica (eso pide sigstore y queda fuera del motor stdlib).
    """
    index = der.find(oid)
    if index < 0:
        return None
    index += len(oid)
    if der[index] == 0x01:            # BOOLEAN critical, opcional
        index += 3
    if der[index] != 0x04:            # OCTET STRING con el valor
        return None
    length, index = _der_length(der, index + 1)
    value = der[index:index + length]
    if value and value[0] == 0x0C:    # UTF8String adentro
        inner, start = _der_length(value, 1)
        value = value[start:start + inner]
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        return None


def _pypi_provenance(name: str, version: str, filename: str) -> dict | None:
    data = _get_json(f"{PYPI}/integrity/{name}/{version}/{filename}/provenance",
                     accept="application/vnd.pypi.integrity.v1+json")
    for bundle in (data or {}).get("attestation_bundles") or []:
        publisher = bundle.get("publisher") or {}
        host = {"GitHub": "github.com", "GitLab": "gitlab.com"}.get(publisher.get("kind"))
        if not host or not publisher.get("repository"):
            continue
        claims = {"repository": f"https://{host}/{publisher['repository']}",
                  "workflow": publisher.get("workflow"), "source": "PyPI (Trusted Publishing)"}
        for attestation in bundle.get("attestations") or []:
            cert = (attestation.get("verification_material") or {}).get("certificate")
            if not cert:
                continue
            der = base64.b64decode(cert)
            commit, ref = _cert_extension(der, _FULCIO_DIGEST), _cert_extension(der, _FULCIO_REF)
            if commit and re.fullmatch(r"[0-9a-f]{40}", commit):
                claims["commit"] = commit
            if ref:
                claims["ref"] = ref
            break
        return {key: value for key, value in claims.items() if value}
    return None


def _pick_wheel(wheels: list[dict]) -> dict | None:
    """Un wheel representativo: el universal si hay, si no el de Linux x86_64."""
    for test in (lambda f: f.endswith("-none-any.whl"),
                 lambda f: "manylinux" in f and "x86_64" in f,
                 lambda f: True):
        for wheel in wheels:
            if test(wheel["filename"]):
                return wheel
    return None


def _pypi_repo(info: dict) -> tuple[str, str] | None:
    urls = dict(info.get("project_urls") or {})
    preferred = ("source", "source code", "repository", "code", "github", "gitlab", "homepage")
    ordered = sorted(urls.items(), key=lambda kv: (
        preferred.index(kv[0].lower()) if kv[0].lower() in preferred else len(preferred)))
    for _label, url in [*ordered, ("home_page", info.get("home_page"))]:
        repo = normalize_repo(url)
        if repo:
            return repo
    return None


def _resolve_pypi(spec: PackageSpec) -> Release:
    path = f"{spec.name}/{spec.version}" if spec.version else spec.name
    doc = _get_json(f"{PYPI}/pypi/{path}/json")
    if doc is None:
        raise RegistryError(f"{spec.label} has no versions published on PyPI (or the project does not exist).")
    info = doc.get("info") or {}
    version = info.get("version") or spec.version or "?"
    files = [f for f in doc.get("urls") or [] if not f.get("yanked")]
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    chosen = [*sdists[:1], *filter(None, [_pick_wheel(wheels)])]
    artifacts = [Artifact("sdist" if f["packagetype"] == "sdist" else "wheel", f["filename"],
                          f["url"], ("sha256", f["digests"]["sha256"]), f.get("size"))
                 for f in chosen if (f.get("digests") or {}).get("sha256")]
    if not artifacts:
        raise RegistryError(f"{spec.label}: there is no sdist or wheel with a published hash.")
    repo = _pypi_repo(info)
    name = info.get("name") or spec.name
    release = Release(
        PackageSpec("pypi", name, version), artifacts,
        repo_url=repo[0] if repo else None, repo_dir=repo[1] if repo else "",
        published_at=min((f.get("upload_time_iso_8601") or "" for f in chosen), default=None),
        other_wheels=max(len(wheels) - 1, 0))
    for artifact in artifacts:
        release.provenance = _pypi_provenance(name, version, artifact.filename)
        if release.provenance:
            break
    return release


def resolve(spec: PackageSpec) -> Release:
    """Metadatos de la versión publicada (la última si no se pidió una)."""
    return _resolve_npm(spec) if spec.ecosystem == "npm" else _resolve_pypi(spec)


# --- detectar los paquetes de un repo --------------------------------------

def detect_packages(files: list[tuple[Path, str]]) -> list[PackageSpec]:
    """Los paquetes que declaran los manifiestos de la raíz del repo."""
    specs: list[PackageSpec] = []
    by_name = {str(path): text for path, text in files if len(path.parts) == 1}
    try:
        package = json.loads(by_name.get("package.json", "null")) or {}
        if isinstance(package, dict) and package.get("name") and not package.get("private"):
            specs.append(PackageSpec("npm", str(package["name"])))
    except ValueError:
        pass
    python_name = None
    try:
        python_name = (tomllib.loads(by_name.get("pyproject.toml", "")).get("project") or {}).get("name")
    except tomllib.TOMLDecodeError:
        pass
    if not python_name:
        match = re.search(r"^\s*name\s*=\s*([\w.-]+)\s*$", by_name.get("setup.cfg", ""), re.MULTILINE) \
            or re.search(r"\bname\s*=\s*['\"]([\w.-]+)['\"]", by_name.get("setup.py", ""))
        python_name = match.group(1) if match else None
    if python_name and _PYPI_NAME.match(python_name):
        specs.append(PackageSpec("pypi", python_name))
    return specs
