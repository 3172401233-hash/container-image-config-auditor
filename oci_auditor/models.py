"""Data model for audit findings."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Severity(enum.IntEnum):
    """Ordered severity levels; higher is worse."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    """A single audit result.

    ``path`` is a JSON path into the input document, prefixed with the
    document root: ``manifest.`` for the image manifest and ``config.``
    for the image config, e.g. ``manifest.layers[0].digest`` or
    ``config.config.User``.
    """

    rule_id: str
    severity: Severity
    path: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity.label}] {self.rule_id} {self.path}: {self.message}"
