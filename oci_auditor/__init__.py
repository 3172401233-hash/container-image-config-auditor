"""Metadata-only OCI image security auditor.

Audits an image manifest, image config and layer list without starting
a container. Reports findings with severities and JSON paths into the
manifest or config documents.
"""

from .auditor import AuditReport, audit
from .models import Finding, Severity
from .validate import parse_config_preserving_duplicates

__all__ = [
    "AuditReport",
    "Finding",
    "Severity",
    "audit",
    "parse_config_preserving_duplicates",
]

__version__ = "0.1.0"
