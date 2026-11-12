"""JinnexGuard: señales de riesgo de un repositorio, con evidencia.

No emite un veredicto binario de "confiable": saca a la luz banderas para que
vetear un repo sea rápido. El motor (`jinnexguard.engine`) es stdlib puro y nunca
ejecuta el código del objetivo; la capa MCP es un envoltorio aparte.
"""

__version__ = "1.0.1"
