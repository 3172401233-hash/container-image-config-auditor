"""Public audit entry point.

Usage::

    from oci_auditor import audit

    report = audit(manifest, config, layers=None, config_bytes=None)
    for finding in report.findings:
        print(finding)

Inputs are parsed JSON documents (dicts/lists); no container is started.
``config`` may also be raw JSON text/bytes, in which case it is parsed
with duplicate-key detection (for duplicate-label checks).
"""

from __future__ import annotations

from typing import Any, List, Optional, Union

from .models import Finding, Severity
from .rules import run_security_rules
from .validate import (
    canonical_config_bytes,
    parse_config_preserving_duplicates,
    validate_config_digest,
    validate_config_structure,
    validate_diff_ids_match_layers,
    validate_layers,
    validate_manifest_structure,
)


class AuditReport:
    """Findings sorted by severity (most severe first)."""

    def __init__(self, findings: List[Finding]) -> None:
        self.findings: List[Finding] = sorted(
            findings, key=lambda f: (-int(f.severity), f.rule_id, f.path)
        )

    @property
    def ok(self) -> bool:
        """True when no finding at MEDIUM severity or above exists."""
        return not any(f.severity >= Severity.MEDIUM for f in self.findings)

    def by_severity(self, minimum: Severity = Severity.INFO) -> List[Finding]:
        return [f for f in self.findings if f.severity >= minimum]

    def __iter__(self):
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def __str__(self) -> str:
        if not self.findings:
            return "no findings"
        return "\n".join(str(f) for f in self.findings)


def audit(
    manifest: Any,
    config: Union[dict, str, bytes],
    layers: Optional[Any] = None,
    config_bytes: Optional[bytes] = None,
) -> AuditReport:
    """Audit an OCI image from its manifest, image config and layer list.

    :param manifest: parsed OCI image manifest (dict).
    :param config: parsed image config (dict) or raw JSON (str/bytes).
        Raw input enables duplicate-label detection.
    :param layers: layer descriptor list; defaults to ``manifest["layers"]``.
    :param config_bytes: exact config blob bytes for digest verification.
        If omitted and ``config`` is a dict, a canonical re-serialization
        is used (see :func:`canonical_config_bytes`).
    """
    findings: List[Finding] = []

    findings.extend(validate_manifest_structure(manifest))
    manifest_ok = isinstance(manifest, dict)

    if isinstance(config, (str, bytes)):
        raw_text = config.decode("utf-8", errors="replace") if isinstance(config, bytes) else config
        if config_bytes is None and isinstance(config, bytes):
            config_bytes = config
        elif config_bytes is None:
            config_bytes = raw_text.encode("utf-8")
        config, dup_findings = parse_config_preserving_duplicates(raw_text)
        findings.extend(dup_findings)

    findings.extend(validate_config_structure(config))

    if layers is None and manifest_ok:
        layers = manifest.get("layers")
    findings.extend(validate_layers(layers))

    if manifest_ok and isinstance(config, dict):
        if config_bytes is None:
            config_bytes = canonical_config_bytes(config)
        findings.extend(validate_config_digest(manifest, config_bytes))
        findings.extend(validate_diff_ids_match_layers(config, layers))

    if isinstance(config, dict):
        findings.extend(run_security_rules(config))

    return AuditReport(findings)
