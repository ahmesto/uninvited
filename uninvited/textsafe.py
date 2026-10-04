"""Small helpers for writing text that other programs will read."""
from __future__ import annotations

from typing import Any


def csv_cell(value: Any) -> Any:
    """A spreadsheet runs a cell that starts with = + - or @ as a formula. A network
    name comes from a registry anyone can write to, and a URL from a request anyone can
    send, so text that begins that way gets a leading apostrophe, which every
    spreadsheet reads as "this is text"."""
    if isinstance(value, str) and value and value[0] in "=+-@\t\r":
        return "'" + value
    return value
