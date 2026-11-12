"""Traer el objetivo a disco de forma segura, sin ejecutar NADA suyo.

Una ruta local se usa tal cual. Una URL se clona en superficie
(`--depth 1`, o completa si se pide el historial) con los hooks de git desactivados, sin submódulos y sin que
git pueda pedir credenciales. En ningún caso se corre código del repo.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

CLONE_TIMEOUT = 120
MAX_FILE_BYTES = 2_000_000          # archivos más grandes no se escanean como texto
# Los lockfiles grandes sí se leen: dicen qué dependencias corren código al instalarse.
LARGE_TEXT_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"}
MAX_LARGE_FILE_BYTES = 30_000_000
# De un binario basta el comienzo: ahí están la firma del formato y sus cabeceras.
BINARY_HEAD_BYTES = 4096
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv",
             "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
# owner/repo o una URL https de un host conocido. Nada de file://, ssh:// ni rutas raras.
_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+$")
_HTTPS = re.compile(r"^https://(?:www\.)?(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)/"
                    r"[\w.-]+/[\w.-]+/?$")


class FetchError(Exception):
    """No se pudo traer el objetivo (URL inválida, clon fallido, etc.)."""


def normalize_url(target: str) -> str | None:
    """Devuelve la URL https a clonar, o None si `target` no es una URL remota."""
    value = target.strip()
    if _SHORTHAND.match(value):
        return f"https://github.com/{value}"
    if _HTTPS.match(value):
        return value.rstrip("/") + (".git" if not value.endswith(".git") else "")
    return None


_NOT_FOUND = re.compile(
    r"repository '.*' not found|Authentication failed|could not read Username|"
    r"terminal prompts disabled", re.I)


def safe_git_env() -> dict[str, str]:
    """Entorno para correr git sobre un repo ajeno: sin prompts ni config del usuario."""
    env = {k: v for k, v in os.environ.items() if k.upper() != "SSH_ASKPASS"}
    return {
        **env,
        "GIT_TERMINAL_PROMPT": "0",   # nunca pedir usuario/clave por terminal
        "GIT_ASKPASS": "",            # vacío = sin helper gráfico (no hay /bin/true en Windows)
        "GCM_INTERACTIVE": "never",   # Git Credential Manager de Windows sin ventanas
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C",                # mensajes de git en inglés, para poder leerlos
    }


# hooksPath apunta a este mismo archivo: una ruta absoluta que es un archivo no puede
# contener hooks en ningún sistema. /dev/null en Windows sería C:\dev\null\<hook>.
_NO_HOOKS = str(Path(__file__).resolve())
# El .git/config del objetivo podría pedir correr comandos: se anulan. Sin helper de
# credenciales ni askpass aunque alguna config los declare.
SAFE_GIT_FLAGS = ("-c", f"core.hooksPath={_NO_HOOKS}", "-c", "core.fsmonitor=false",
                  "-c", "credential.helper=", "-c", "core.askPass=")
# La salida de git es UTF-8; en Windows la codificación local sería cp1252.
_GIT_TEXT = {"encoding": "utf-8", "errors": "replace"}


def _safe_clone(url: str, destination: Path, *, full_history: bool = False) -> None:
    env = safe_git_env()
    cmd = [
        "git", *SAFE_GIT_FLAGS,             # un repo no corre sus hooks al clonarse
        "-c", "protocol.ext.allow=never",
        "clone", "--no-tags", "--recurse-submodules=no",
        *(() if full_history else ("--depth", "1", "--single-branch")),
        url, str(destination),
    ]
    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, **_GIT_TEXT,
            timeout=CLONE_TIMEOUT, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FetchError(f"The clone took longer than {CLONE_TIMEOUT}s: {url}") from exc
    except FileNotFoundError as exc:
        raise FetchError("git is not available on this system.") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        if _NOT_FOUND.search(result.stderr or ""):
            # Sin credenciales, GitHub responde igual a un repo privado que a uno inexistente.
            raise FetchError(f"Repository not found or private: {url}")
        raise FetchError(f"git clone failed: {detail[-1] if detail else 'unknown error'}")


@contextmanager
def acquire(target: str, *, full_history: bool = False) -> Iterator[tuple[Path, str]]:
    """Context manager: entrega (ruta, origen) con origen 'local' o 'clone'.

    El directorio del clon se borra al salir; una ruta local no se toca.
    """
    url = normalize_url(target)
    path = Path(target.strip()).expanduser()
    # `owner/repo` también es una ruta relativa válida: si esa carpeta existe, es lo que
    # la persona tiene delante. Para el repo de GitHub del mismo nombre, la URL completa.
    if url is not None and _SHORTHAND.match(target.strip()) and path.is_dir():
        url = None
    if url is None:
        if not path.is_dir():
            raise FetchError(f"Not a supported URL or an existing folder: {target}")
        yield path.resolve(), "local"
        return
    with tempfile.TemporaryDirectory(prefix="jinnexguard-", ignore_cleanup_errors=True) as tmp:
        destination = Path(tmp) / "repo"
        _safe_clone(url, destination, full_history=full_history)
        yield destination, "clone"


def clone_at_ref(url: str, refs: list[str], destination: Path) -> str | None:
    """Trae en superficie el primer ref que exista (commit, tag o rama) y lo deja en disco.

    Devuelve el ref que funcionó, o None si ninguno. Igual que el clon normal:
    sin hooks, sin submódulos, sin credenciales.
    """
    clone_url = normalize_url(url)
    if clone_url is None:
        raise FetchError(f"Do not know how to clone {url}")
    env = safe_git_env()
    git = ["git", "-C", str(destination), *SAFE_GIT_FLAGS, "-c", "protocol.ext.allow=never"]
    destination.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["git", "init", "-q", str(destination)], env=env, capture_output=True,
                       timeout=CLONE_TIMEOUT, check=True)
        for ref in refs:
            fetched = subprocess.run(
                [*git, "fetch", "-q", "--depth", "1", "--no-tags", "--recurse-submodules=no",
                 clone_url, ref], env=env, capture_output=True, timeout=CLONE_TIMEOUT, check=False)
            if fetched.returncode != 0:
                continue
            checkout = subprocess.run([*git, "checkout", "-q", "FETCH_HEAD"], env=env,
                                      capture_output=True, timeout=CLONE_TIMEOUT, check=False)
            if checkout.returncode == 0:
                return ref
    except subprocess.TimeoutExpired as exc:
        raise FetchError(f"The clone took longer than {CLONE_TIMEOUT}s: {url}") from exc
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise FetchError(f"git could not prepare the clone: {exc}") from exc
    return None


def _is_probably_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def git_tracked_files(root: Path) -> list[Path] | None:
    """Lo que git incluiría en un commit: versionados + nuevos no ignorados.

    Lo ignorado (.env, venv/, logs, bases locales) no es parte del repo, así que
    no se reporta. None si `root` no es la raíz de un repo git o git falla.
    """
    if not (root / ".git").exists():
        return None
    cmd = ["git", "-C", str(root), *SAFE_GIT_FLAGS,
           "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    try:
        result = subprocess.run(cmd, env=safe_git_env(), capture_output=True,
                                timeout=CLONE_TIMEOUT, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if result.returncode != 0:
        return None
    names = result.stdout.decode("utf-8", errors="replace").split("\0")
    return [Path(name) for name in dict.fromkeys(names) if name]


def git_origin_url(root: Path) -> str | None:
    """La URL del remoto `origin` de un clon local, para pedir su reputación."""
    if not (root / ".git").exists():
        return None
    cmd = ["git", "-C", str(root), *SAFE_GIT_FLAGS, "remote", "get-url", "origin"]
    try:
        result = subprocess.run(cmd, env=safe_git_env(), capture_output=True, text=True,
                                **_GIT_TEXT, timeout=10, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    url = result.stdout.strip()
    return url if result.returncode == 0 and url else None


def _walk(root: Path, skip_dirs: frozenset[str] | set[str] = SKIP_DIRS) -> Iterator[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            yield (Path(current) / name).relative_to(root)


def iter_text_files(root: Path, selected: list[Path] | None = None, *,
                    skip_dirs: frozenset[str] | set[str] = SKIP_DIRS,
                    binaries: list[tuple[PurePosixPath, bytes, int]] | None = None
                    ) -> Iterator[tuple[PurePosixPath, str]]:
    """Entrega (ruta_relativa, texto) de los archivos de texto del repo.

    La ruta sale siempre con `/`: es la que va al reporte y debe ser igual en Windows.

    `selected` limita el recorrido a esas rutas (p. ej. las de git_tracked_files);
    sin él se recorre la carpeta entera. Un paquete publicado se lee con
    `skip_dirs=frozenset()`: ahí `dist/` es justo lo que se instala.

    Con `binaries`, cada archivo binario agrega ahí (ruta, comienzo, tamaño), también
    los que son demasiado grandes para leerse como texto: así se recorre una sola vez.
    """
    paths = _walk(root, skip_dirs) if selected is None else (
        p for p in selected if not skip_dirs.intersection(p.parts))
    for relative in paths:
        full = root / relative
        posix = PurePosixPath(relative.as_posix())
        try:
            limit = MAX_LARGE_FILE_BYTES if relative.name in LARGE_TEXT_NAMES else MAX_FILE_BYTES
            if full.is_symlink() or not full.is_file():
                continue
            size = full.stat().st_size
            if size > limit:
                if binaries is not None:
                    with full.open("rb") as handle:
                        head = handle.read(BINARY_HEAD_BYTES)
                    if _is_probably_binary(head[:1024]):
                        binaries.append((posix, head, size))
                continue
            raw = full.read_bytes()
        except OSError:
            continue
        if _is_probably_binary(raw[:1024]):
            if binaries is not None:
                binaries.append((posix, raw[:BINARY_HEAD_BYTES], size))
            continue
        yield posix, raw.decode("utf-8", errors="replace")
