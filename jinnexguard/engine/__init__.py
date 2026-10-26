"""Motor de análisis de JinnexGuard: stdlib puro, nunca ejecuta el objetivo."""

from jinnexguard.engine.report import Finding, Report, Severity
from jinnexguard.engine.runner import assess

__all__ = ["Finding", "Report", "Severity", "assess"]
