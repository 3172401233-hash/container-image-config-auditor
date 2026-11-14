"""Security rules evaluated against the image config document.

Runtime-relevant settings (privileged, host namespaces, binds, added
capabilities, readonly rootfs) are read from the ``HostConfig`` object
embedded in the image config, as produced by Docker-compatible builds.
All checks are metadata-only; no container is ever started.
"""

from __future__ import annotations

import posixpath
from typing import Any, Dict, List, Tuple

from .models import Finding, Severity

# Capabilities that grant broad control over the host or other containers.
CRITICAL_CAPABILITIES = {"ALL", "SYS_ADMIN"}
HIGH_CAPABILITIES = {
    "BPF",
    "CHECKPOINT_RESTORE",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "MKNOD",
    "NET_ADMIN",
    "NET_RAW",
    "PERFMON",
    "SETFCAP",
    "SETGID",
    "SETUID",
    "SYS_BOOT",
    "SYS_CHROOT",
    "SYS_MODULE",
    "SYS_PTRACE",
    "SYS_RAWIO",
}

# Sensitive host paths: mounting any of these (or an ancestor of them)
# into a container exposes host state or control interfaces.
SENSITIVE_HOST_PATHS: Dict[str, Tuple[Severity, str]] = {
    "/var/run/docker.sock": (Severity.CRITICAL, "Docker daemon socket"),
    "/run/docker.sock": (Severity.CRITICAL, "Docker daemon socket"),
    "/var/run/containerd/containerd.sock": (
        Severity.CRITICAL,
        "containerd daemon socket",
    ),
    "/run/containerd/containerd.sock": (
        Severity.CRITICAL,
        "containerd daemon socket",
    ),
    "/var/run/crio/crio.sock": (Severity.CRITICAL, "CRI-O daemon socket"),
    "/run/crio/crio.sock": (Severity.CRITICAL, "CRI-O daemon socket"),
    "/var/lib/docker": (Severity.HIGH, "Docker daemon data directory"),
    "/var/lib/containerd": (Severity.HIGH, "containerd data directory"),
    "/var/lib/kubelet": (Severity.HIGH, "kubelet state directory"),
    "/etc/kubernetes": (Severity.HIGH, "Kubernetes configuration"),
    "/proc": (Severity.HIGH, "host /proc"),
    "/sys": (Severity.HIGH, "host /sys"),
    "/dev": (Severity.HIGH, "host device nodes"),
    "/etc": (Severity.HIGH, "host /etc"),
    "/root": (Severity.HIGH, "host root home directory"),
    "/var/run": (Severity.HIGH, "host runtime state directory"),
    "/run": (Severity.HIGH, "host runtime state directory"),
    "/": (Severity.CRITICAL, "host filesystem root"),
}

# Substrings in environment variable NAMES that suggest a baked-in secret.
# Only names are inspected; values are never interpreted.
SUSPICIOUS_ENV_NAME_PARTS = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "AUTH_KEY",
    "SESSION_KEY",
)


def _normalize_capability(cap: Any) -> str:
    name = str(cap).strip().upper()
    if name.startswith("CAP_"):
        name = name[len("CAP_"):]
    return name


def _path_contains(parent: str, child: str) -> bool:
    """True if ``parent`` equals or is an ancestor directory of ``child``."""
    parent = posixpath.normpath(parent)
    child = posixpath.normpath(child)
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def check_user(config: Dict[str, Any]) -> List[Finding]:
    inner = config.get("config")
    user = inner.get("User") if isinstance(inner, dict) else None
    path = "config.config.User"
    if user is None or str(user).strip() == "":
        return [
            Finding(
                "root-user",
                Severity.HIGH,
                path,
                "no user configured; container defaults to running as root (uid 0)",
            )
        ]
    text = str(user).strip()
    user_part = text.split(":", 1)[0]
    if user_part == "root" or user_part == "0":
        return [
            Finding(
                "root-user",
                Severity.HIGH,
                path,
                f"container is configured to run as root (User={text!r})",
            )
        ]
    return []


def check_rootfs_writable(config: Dict[str, Any]) -> List[Finding]:
    host_config = config.get("HostConfig")
    readonly = (
        host_config.get("ReadonlyRootfs") if isinstance(host_config, dict) else None
    )
    if readonly is True:
        return []
    return [
        Finding(
            "writable-rootfs",
            Severity.LOW,
            "config.HostConfig.ReadonlyRootfs",
            "root filesystem is not forced read-only "
            "(ReadonlyRootfs is not true)",
        )
    ]


def check_host_config(config: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    host_config = config.get("HostConfig")
    if not isinstance(host_config, dict):
        return findings

    if host_config.get("Privileged") is True:
        findings.append(
            Finding(
                "privileged",
                Severity.CRITICAL,
                "config.HostConfig.Privileged",
                "container is configured to run in privileged mode",
            )
        )

    network_mode = str(host_config.get("NetworkMode") or "").lower()
    if network_mode == "host":
        findings.append(
            Finding(
                "host-network",
                Severity.HIGH,
                "config.HostConfig.NetworkMode",
                "container shares the host network namespace",
            )
        )

    pid_mode = str(host_config.get("PidMode") or "").lower()
    if pid_mode == "host":
        findings.append(
            Finding(
                "host-pid",
                Severity.HIGH,
                "config.HostConfig.PidMode",
                "container shares the host PID namespace",
            )
        )

    ipc_mode = str(host_config.get("IpcMode") or "").lower()
    if ipc_mode == "host":
        findings.append(
            Finding(
                "host-ipc",
                Severity.MEDIUM,
                "config.HostConfig.IpcMode",
                "container shares the host IPC namespace",
            )
        )

    cap_add = host_config.get("CapAdd")
    if isinstance(cap_add, list):
        for index, cap in enumerate(cap_add):
            name = _normalize_capability(cap)
            if name in CRITICAL_CAPABILITIES:
                findings.append(
                    Finding(
                        "dangerous-capability",
                        Severity.CRITICAL,
                        f"config.HostConfig.CapAdd[{index}]",
                        f"capability {name} grants near-root control of the host",
                    )
                )
            elif name in HIGH_CAPABILITIES:
                findings.append(
                    Finding(
                        "dangerous-capability",
                        Severity.HIGH,
                        f"config.HostConfig.CapAdd[{index}]",
                        f"capability {name} is dangerous to grant to a container",
                    )
                )

    findings.extend(_check_mounts(host_config))
    return findings


def _sensitive_match(source: str) -> Tuple[str, Severity, str] | None:
    """Return the most severe sensitive-path match for a mount source."""
    best = None
    for sensitive, (severity, description) in SENSITIVE_HOST_PATHS.items():
        # Flag if the mount source is the sensitive path, an ancestor of
        # it (mounting "/" exposes docker.sock), or inside it.
        if _path_contains(source, sensitive) or _path_contains(sensitive, source):
            if best is None or severity > best[1]:
                best = (sensitive, severity, description)
    return best


def _check_mounts(host_config: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    binds = host_config.get("Binds")
    if isinstance(binds, list):
        for index, bind in enumerate(binds):
            if not isinstance(bind, str):
                continue
            source = bind.split(":", 1)[0].strip()
            if not source.startswith("/"):
                continue
            match = _sensitive_match(source)
            if match:
                sensitive, severity, description = match
                findings.append(
                    Finding(
                        "sensitive-host-path",
                        severity,
                        f"config.HostConfig.Binds[{index}]",
                        f"bind mount {source!r} exposes {description} ({sensitive})",
                    )
                )

    mounts = host_config.get("Mounts")
    if isinstance(mounts, list):
        for index, mount in enumerate(mounts):
            if not isinstance(mount, dict):
                continue
            source = mount.get("Source") or mount.get("source")
            if not isinstance(source, str) or not source.startswith("/"):
                continue
            match = _sensitive_match(source)
            if match:
                sensitive, severity, description = match
                findings.append(
                    Finding(
                        "sensitive-host-path",
                        severity,
                        f"config.HostConfig.Mounts[{index}].Source",
                        f"mount {source!r} exposes {description} ({sensitive})",
                    )
                )
    return findings


def check_env_names(config: Dict[str, Any]) -> List[Finding]:
    """Flag suspicious environment variable NAMES only.

    Values are never inspected or interpreted; a variable named
    ``APP_TOKEN`` is flagged regardless of what it contains.
    """
    findings: List[Finding] = []
    inner = config.get("config")
    env = inner.get("Env") if isinstance(inner, dict) else None
    if not isinstance(env, list):
        return findings
    for index, entry in enumerate(env):
        if not isinstance(entry, str):
            continue
        name = entry.split("=", 1)[0].strip().upper()
        for part in SUSPICIOUS_ENV_NAME_PARTS:
            if part in name:
                findings.append(
                    Finding(
                        "suspicious-env-name",
                        Severity.MEDIUM,
                        f"config.config.Env[{index}]",
                        f"environment variable name {name!r} suggests a secret "
                        "baked into the image (name-only check)",
                    )
                )
                break
    return findings


def run_security_rules(config: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(check_user(config))
    findings.extend(check_rootfs_writable(config))
    findings.extend(check_host_config(config))
    findings.extend(check_env_names(config))
    return findings
