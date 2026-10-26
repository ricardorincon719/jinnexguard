"""Programas, drivers y bibliotecas ya compilados dentro del repo.

Un binario no se puede leer como el código: nadie puede comprobar que salga del
fuente que lo acompaña. Se reconoce por su firma de formato (PE de Windows, ELF de
Linux, Mach-O de macOS), nunca se ejecuta. Pesa más si es un driver de kernel o si
el código o las instrucciones del agente lo nombran: entonces algo lo lanza.
"""

from __future__ import annotations

import re
import struct
from pathlib import PurePosixPath

from jinnexguard.engine.checks.agents import _is_instruction_file
from jinnexguard.engine.checks.dangerous_patterns import (
    _CODE_SUFFIXES, _COMMENT, _EXEC_HINT, _TEST_HINT, _adjust)
from jinnexguard.engine.report import Finding, Severity

MAX_INDIVIDUAL = 10   # más allá, los binarios van juntos en un solo hallazgo
MAX_NAMED = 300       # nombres que se buscan en el código (un repo con miles de fixtures)
EXEC_WINDOW = 15      # líneas alrededor de la mención donde buscar la llamada que ejecuta
# Un nombre que es una palabra suelta ("binary", "runtime") aparece en cualquier texto.
_FILE_LIKE = re.compile(r"[.\-_\d]")
# Archivos desde donde se lanza o se carga algo, además del código.
_LAUNCHER_SUFFIXES = {"", ".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1", ".mk"}
# Desde aquí, nombrar un programa ya es lanzarlo (un script, o el agente que lo sigue).
_RUNS_SUFFIXES = {"", ".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1"}
_LAUNCHER_NAMES = {"package.json", "Makefile", "justfile", "Taskfile.yml", "setup.py",
                   "pyproject.toml"}

_PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64", 0x1C4: "ARM"}
_ELF_MACHINES = {3: "x86", 62: "x86-64", 183: "ARM64", 40: "ARM", 243: "RISC-V"}
_MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64"}
_MACHO_MAGICS = {b"\xfe\xed\xfa\xce": ">", b"\xfe\xed\xfa\xcf": ">",
                 b"\xce\xfa\xed\xfe": "<", b"\xcf\xfa\xed\xfe": "<"}

DRIVER, PROGRAM, LIBRARY = "driver", "program", "library"


def _pe(path: PurePosixPath, head: bytes) -> tuple[str, str]:
    kind, signed, arch = PROGRAM, "", ""
    if len(head) >= 0x40:
        offset = struct.unpack_from("<I", head, 0x3C)[0]
        if head[offset:offset + 4] == b"PE\0\0" and len(head) >= offset + 24 + 72:
            machine, characteristics = struct.unpack_from("<H", head, offset + 4)[0], \
                struct.unpack_from("<H", head, offset + 22)[0]
            optional = offset + 24
            magic, subsystem = struct.unpack_from("<H", head, optional)[0], \
                struct.unpack_from("<H", head, optional + 68)[0]
            arch = _PE_MACHINES.get(machine, "")
            if subsystem == 1:            # NATIVE: corre en el kernel (o antes que Windows)
                kind = DRIVER
            elif characteristics & 0x2000:   # IMAGE_FILE_DLL
                kind = LIBRARY
            # El directorio 4 (SECURITY) guarda la firma Authenticode; vacío = sin firmar.
            security = optional + (96 if magic == 0x10B else 112) + 4 * 8
            if len(head) >= security + 8:
                signed = ("signed (signature not verified)"
                          if struct.unpack_from("<I", head, security + 4)[0] else "unsigned")
    if path.suffix.lower() == ".sys":
        kind = DRIVER
    names = {DRIVER: "Windows kernel driver", PROGRAM: "Windows program", LIBRARY: "Windows DLL"}
    return kind, ", ".join(x for x in (f"{names[kind]} ({arch})" if arch else names[kind],
                                       signed) if x)


def _elf(path: PurePosixPath, head: bytes) -> tuple[str, str]:
    endian = "<" if head[5:6] != b"\x02" else ">"
    kind_code, machine = struct.unpack_from(endian + "HH", head, 16) if len(head) >= 20 else (0, 0)
    name = path.name.lower()
    if name.endswith(".ko"):
        kind, label = DRIVER, "Linux kernel module"
    elif kind_code == 1:   # ET_REL: un .o suelto
        kind, label = LIBRARY, "Linux object file"
    elif ".so" in name and (name.endswith(".so") or re.search(r"\.so(\.\d+)+$", name)):
        kind, label = LIBRARY, "Linux shared library"
    else:
        kind, label = PROGRAM, "Linux program"
    arch = _ELF_MACHINES.get(machine)
    return kind, f"{label} ({arch})" if arch else label


def _macho(path: PurePosixPath, head: bytes, endian: str | None) -> tuple[str, str]:
    kind, label, arch = PROGRAM, "macOS program", ""
    if endian and len(head) >= 16:
        cpu, filetype = struct.unpack_from(endian + "I", head, 4)[0], \
            struct.unpack_from(endian + "I", head, 12)[0]
        arch = _MACHO_CPUS.get(cpu, "")
        if filetype == 0xB:          # MH_KEXT_BUNDLE
            kind, label = DRIVER, "macOS kernel extension"
        elif filetype in (6, 8):     # MH_DYLIB, MH_BUNDLE
            kind, label = LIBRARY, "macOS library"
    elif path.suffix.lower() == ".dylib":
        kind, label = LIBRARY, "macOS library"
    else:
        label = "macOS universal binary"
    return kind, f"{label} ({arch})" if arch else label


def classify(path: PurePosixPath, head: bytes) -> tuple[str, str] | None:
    """(tipo, descripción) si el comienzo del archivo es un ejecutable nativo; si no, None."""
    if head[:2] == b"MZ":
        return _pe(path, head)
    if head[:4] == b"\x7fELF":
        return _elf(path, head)
    if head[:4] in _MACHO_MAGICS:
        return _macho(path, head, _MACHO_MAGICS[head[:4]])
    # 0xCAFEBABE es Mach-O universal y también una clase de Java: el universal lleva
    # pocas arquitecturas donde Java pone su versión (≥ 45).
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and len(head) >= 8 \
            and struct.unpack_from(">I", head, 4)[0] < 40:
        return _macho(path, head, None)
    return None


def _is_launcher(path: PurePosixPath) -> bool:
    suffix = path.suffix.lower()
    return (suffix in _CODE_SUFFIXES or suffix in _LAUNCHER_SUFFIXES
            or path.name in _LAUNCHER_NAMES or _is_instruction_file(path))


def _references(names: list[str], files) -> dict[str, tuple[str, int, bool]]:
    """Dónde nombra el código o las instrucciones a cada binario: (archivo, línea, lo lanza).

    Lo lanza si lo nombra un script o una instrucción para el agente, o si cerca de la
    mención hay una llamada que ejecuta. `include_bytes!` o una lista de hashes solo lo
    nombran. Gana la primera mención que lo lanza; si no hay, la primera que lo nombra.
    """
    if not names:
        return {}
    pattern = re.compile(r"(?<![\w.-])(" + "|".join(map(re.escape, names)) + r")(?![\w-])")
    found: dict[str, tuple[str, int, bool]] = {}
    for path, text in files:
        posix = PurePosixPath(str(path))
        if not _is_launcher(posix):
            continue
        always_runs = posix.suffix.lower() in _RUNS_SUFFIXES or _is_instruction_file(posix)
        lines: list[str] | None = None
        for match in pattern.finditer(text):
            name = match.group(1)
            if found.get(name, ("", 0, False))[2]:
                continue
            if lines is None:
                lines = text.splitlines()
            lineno = text.count("\n", 0, match.start()) + 1
            if lineno <= len(lines) and _COMMENT.match(lines[lineno - 1]):
                continue
            window = lines[max(0, lineno - 1 - EXEC_WINDOW):lineno + EXEC_WINDOW]
            runs = always_runs or any(_EXEC_HINT.search(line) for line in window)
            if runs or name not in found:
                found[name] = (str(path), lineno, runs)
        if len(found) == len(names) and all(runs for *_, runs in found.values()):
            break
    return found


_TEXTS = {
    DRIVER: ("Precompiled kernel driver",
             "A driver runs inside the operating system kernel, with full control of the "
             "machine and below any antivirus. It ships compiled: nobody can check that it "
             "matches its source."),
    PROGRAM: ("Precompiled program",
              "A compiled program cannot be read like code: nobody can check that it matches "
              "its source, or that it does only what the README says."),
    LIBRARY: ("Precompiled library",
              "Compiled code loaded by the project: it cannot be read, and nobody can check "
              "that it matches its source."),
}
_BASE = {DRIVER: Severity.HIGH, PROGRAM: Severity.MEDIUM, LIBRARY: Severity.LOW}


def run(binaries: list[tuple[PurePosixPath, bytes, int]], files) -> list[Finding]:
    native = [(path, size, *kind) for path, head, size in binaries
              if (kind := classify(path, head)) is not None]
    if not native:
        return []
    refs = _references(sorted({path.name for path, *_ in native if len(path.name) >= 4
                               and _FILE_LIKE.search(path.name)})[:MAX_NAMED], files)
    candidates: list[tuple[Severity, Finding]] = []
    for path, size, kind, label in native:
        where = refs.get(path.name)
        severity = _BASE[kind]
        title, detail = _TEXTS[kind]
        if where and where[2] and kind != DRIVER:
            severity = Severity(int(severity) + 1)
            title += " that the code runs" if kind == PROGRAM else " that the code loads"
            detail += " A script, the code or the agent instructions start it."
        if _TEST_HINT.search(str(path)):
            severity = _adjust(severity, 1)   # binarios de ejemplo de un parser o un test
        evidence = f"{label}, {size:,} bytes" + (f"; named at {where[0]}:{where[1]}" if where else "")
        candidates.append((severity, Finding(severity, "binary", f"{title} ({path})", detail,
                                             evidence=evidence, path=str(path))))
    candidates.sort(key=lambda item: -int(item[0]))
    findings = [finding for _, finding in candidates[:MAX_INDIVIDUAL]]
    rest = candidates[MAX_INDIVIDUAL:]
    if rest:
        findings.append(Finding(
            rest[0][0], "binary", f"{len(rest)} more precompiled binaries",
            "More compiled files that cannot be read like code. The list shows where they are.",
            evidence=", ".join(f.path for _, f in rest[:6]) + (
                f"  (+{len(rest) - 6} more)" if len(rest) > 6 else ""),
            path=rest[0][1].path))
    return findings
