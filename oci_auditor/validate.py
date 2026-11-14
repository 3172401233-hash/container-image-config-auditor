"""Structural validation of OCI manifests, configs and layer lists.

Covers digest verification/format, duplicate labels and missing fields.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, List, Optional, Tuple

from .models import Finding, Severity

# OCI digest grammar: algorithm ":" encoded
# algorithm := [a-z0-9]+ (separator [a-z0-9]+)*, separator in {+, ., _, -}
# encoded   := [A-Za-z0-9=_-]+ (at least 32 chars in practice)
DIGEST_RE = re.compile(r"^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]{32,}$")

MANIFEST_REQUIRED_FIELDS = ("schemaVersion", "config", "layers")
CONFIG_REQUIRED_FIELDS = ("architecture", "os", "rootfs")
ROOTFS_REQUIRED_FIELDS = ("type", "diff_ids")


def is_valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(DIGEST_RE.match(value))


def canonical_config_bytes(config: dict) -> bytes:
    """Deterministic serialization used when raw config bytes are absent.

    Prefer passing the original config bytes to ``audit``; digests are
    defined over the exact stored blob, and re-serialization may differ.
    """
    return json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_manifest_structure(manifest: Any) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(manifest, dict):
        findings.append(
            Finding(
                "malformed-manifest",
                Severity.CRITICAL,
                "manifest",
                "manifest is not a JSON object",
            )
        )
        return findings
    for field_name in MANIFEST_REQUIRED_FIELDS:
        if field_name not in manifest:
            findings.append(
                Finding(
                    "missing-field",
                    Severity.HIGH,
                    f"manifest.{field_name}",
                    f"manifest is missing required field '{field_name}'",
                )
            )
    return findings


def validate_config_structure(config: Any) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(config, dict):
        findings.append(
            Finding(
                "malformed-config",
                Severity.CRITICAL,
                "config",
                "image config is not a JSON object",
            )
        )
        return findings
    for field_name in CONFIG_REQUIRED_FIELDS:
        if field_name not in config:
            findings.append(
                Finding(
                    "missing-field",
                    Severity.HIGH,
                    f"config.{field_name}",
                    f"image config is missing required field '{field_name}'",
                )
            )
    rootfs = config.get("rootfs")
    if isinstance(rootfs, dict):
        for field_name in ROOTFS_REQUIRED_FIELDS:
            if field_name not in rootfs:
                findings.append(
                    Finding(
                        "missing-field",
                        Severity.HIGH,
                        f"config.rootfs.{field_name}",
                        f"rootfs is missing required field '{field_name}'",
                    )
                )
    return findings


def validate_config_digest(
    manifest: dict, config_bytes: bytes
) -> List[Finding]:
    """Verify manifest.config.digest matches the config blob content."""
    findings: List[Finding] = []
    config_desc = manifest.get("config")
    if not isinstance(config_desc, dict):
        return findings
    digest = config_desc.get("digest")
    path = "manifest.config.digest"
    if digest is None:
        findings.append(
            Finding(
                "missing-field",
                Severity.HIGH,
                path,
                "manifest config descriptor has no digest",
            )
        )
        return findings
    if not is_valid_digest(digest):
        findings.append(
            Finding(
                "invalid-digest",
                Severity.HIGH,
                path,
                f"config digest {digest!r} does not match the OCI digest format",
            )
        )
        return findings
    algorithm, _, expected = digest.partition(":")
    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        findings.append(
            Finding(
                "unsupported-digest-algorithm",
                Severity.MEDIUM,
                path,
                f"digest algorithm {algorithm!r} is not supported for verification",
            )
        )
        return findings
    hasher.update(config_bytes)
    actual = hasher.hexdigest()
    if actual != expected.lower():
        findings.append(
            Finding(
                "config-digest-mismatch",
                Severity.CRITICAL,
                path,
                "config blob hash does not match manifest.config.digest "
                f"(expected {expected}, computed {actual})",
            )
        )
    return findings


def validate_layers(layers: Any, source_path: str = "manifest.layers") -> List[Finding]:
    """Validate the layer list shape and each layer digest format."""
    findings: List[Finding] = []
    if layers is None:
        findings.append(
            Finding(
                "missing-field",
                Severity.HIGH,
                source_path,
                "no layer list provided and manifest has no 'layers' field",
            )
        )
        return findings
    if not isinstance(layers, list):
        findings.append(
            Finding(
                "malformed-layers",
                Severity.HIGH,
                source_path,
                f"layer list must be a JSON array, got {type(layers).__name__}",
            )
        )
        return findings
    if not layers:
        findings.append(
            Finding(
                "malformed-layers",
                Severity.MEDIUM,
                source_path,
                "layer list is empty; OCI manifests require at least one layer",
            )
        )
        return findings
    for index, layer in enumerate(layers):
        path = f"{source_path}[{index}]"
        if not isinstance(layer, dict):
            findings.append(
                Finding(
                    "malformed-layers",
                    Severity.HIGH,
                    path,
                    f"layer entry must be a JSON object, got {type(layer).__name__}",
                )
            )
            continue
        digest = layer.get("digest")
        if digest is None:
            findings.append(
                Finding(
                    "missing-field",
                    Severity.HIGH,
                    f"{path}.digest",
                    "layer descriptor is missing required field 'digest'",
                )
            )
        elif not is_valid_digest(digest):
            findings.append(
                Finding(
                    "invalid-layer-digest",
                    Severity.HIGH,
                    f"{path}.digest",
                    f"layer digest {digest!r} does not match the OCI digest format",
                )
            )
    return findings


def validate_diff_ids_match_layers(config: dict, layers: Any) -> List[Finding]:
    """Check rootfs.diff_ids count matches the number of layers."""
    findings: List[Finding] = []
    if not isinstance(layers, list) or not layers:
        return findings
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict):
        return findings
    diff_ids = rootfs.get("diff_ids")
    if not isinstance(diff_ids, list):
        return findings
    if len(diff_ids) != len(layers):
        findings.append(
            Finding(
                "diffids-layer-count-mismatch",
                Severity.MEDIUM,
                "config.rootfs.diff_ids",
                f"rootfs has {len(diff_ids)} diff_ids but manifest lists "
                f"{len(layers)} layers",
            )
        )
    return findings


class _Pairs(list):
    """Marker for raw JSON object pairs before duplicate resolution."""


def parse_config_preserving_duplicates(
    raw: str,
) -> Tuple[Optional[dict], List[Finding]]:
    """Parse image config JSON, reporting duplicate keys.

    Returns ``(config, findings)``. ``config`` is ``None`` on parse error.
    Duplicate keys inside ``config.config.Labels`` are reported as
    ``duplicate-label``; duplicates elsewhere as ``duplicate-key``.
    """
    try:
        tree = json.loads(raw, object_pairs_hook=_Pairs)
    except (json.JSONDecodeError, TypeError) as exc:
        return None, [
            Finding(
                "malformed-config",
                Severity.CRITICAL,
                "config",
                f"image config is not valid JSON: {exc}",
            )
        ]

    findings: List[Finding] = []

    def build(node: Any, path: str) -> Any:
        if isinstance(node, _Pairs):
            out = {}
            for key, value in node:
                if key in out:
                    rule = (
                        "duplicate-label"
                        if path == "config.config.Labels"
                        else "duplicate-key"
                    )
                    findings.append(
                        Finding(
                            rule,
                            Severity.MEDIUM,
                            f"{path}.{key}",
                            f"duplicate key {key!r} in JSON object at {path}",
                        )
                    )
                out[key] = build(value, f"{path}.{key}")
            return out
        if isinstance(node, list):
            return [build(item, f"{path}[{i}]") for i, item in enumerate(node)]
        return node

    return build(tree, "config"), findings
