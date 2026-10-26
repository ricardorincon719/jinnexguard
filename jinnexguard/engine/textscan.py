"""Búsqueda rápida de líneas candidatas antes de correr expresiones regulares caras.

Las regex de Python sin un literal al principio prueban en cada carácter: en un
repo de un millón de líneas eso son decenas de segundos. Acá se buscan primero
literales con `str.find` (en C) y solo las líneas que los contienen pasan a la
regex. Un literal requerido está en toda línea que la regex marcaría, así que el
resultado es el mismo.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable, Iterator
from itertools import accumulate


def _positions(haystack: str, literals: Iterable[str]) -> Iterator[int]:
    for literal in literals:
        start = haystack.find(literal)
        while start != -1:
            yield start
            start = haystack.find(literal, start + 1)


def lines_with(text: str, literals: Iterable[str], *, lower: bool = False
               ) -> list[tuple[int, str]]:
    """(número, línea) de las líneas que contienen alguno de los literales, en orden.

    Numera igual que `text.splitlines()`. Con `lower=True` los literales deben ir en
    minúsculas y se comparan contra el texto en minúsculas.
    """
    literals = tuple(literals)
    haystack = text.lower() if lower else text
    if len(haystack) != len(text):   # minúsculas que cambian el largo (raro): línea a línea
        return [(n, line) for n, line in enumerate(text.splitlines(), start=1)
                if any(lit in line.lower() for lit in literals)]
    positions = list(_positions(haystack, literals))
    if not positions:
        return []
    lines = text.splitlines(keepends=True)
    starts = list(accumulate((len(line) for line in lines), initial=0))
    indexes = sorted({bisect_right(starts, p) - 1 for p in positions})
    return [(i + 1, (lines[i].splitlines() or [""])[0]) for i in indexes]
