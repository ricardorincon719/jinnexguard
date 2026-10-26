"""Chequeos del motor. Cada uno recibe los archivos ya leídos y devuelve hallazgos.

Un chequeo roto nunca debe tumbar al resto: el runner los aísla. La firma común
es `run(files) -> list[Finding]`, donde files es una lista de (ruta_relativa, texto).
"""

from jinnexguard.engine.checks import (
    agents,
    dangerous_patterns,
    impersonation,
    install_scripts,
    secrets,
    supply_chain,
)

# Chequeos que operan sobre los archivos del repo.
FILE_CHECKS = (install_scripts, dangerous_patterns, impersonation, secrets, agents, supply_chain)

__all__ = ["FILE_CHECKS", "install_scripts", "dangerous_patterns", "impersonation", "secrets",
           "agents", "supply_chain"]
