"""Tests built on hand-crafted OCI manifest/config JSON documents."""

import hashlib
import json
import unittest

from oci_auditor import Severity, audit
from oci_auditor.validate import canonical_config_bytes

LAYER_DIGEST = "sha256:" + "a" * 64


def make_config(**overrides):
    config = {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:" + "b" * 64],
        },
        "config": {
            "User": "1000:1000",
            "Env": ["PATH=/usr/local/bin"],
            "Labels": {"maintainer": "team@example.com"},
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "NetworkMode": "bridge",
            "PidMode": "private",
        },
    }
    config.update(overrides)
    return config


def make_manifest(config, layers=None, digest=None):
    if digest is None:
        digest = "sha256:" + hashlib.sha256(
            canonical_config_bytes(config)
        ).hexdigest()
    if layers is None:
        layers = [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": LAYER_DIGEST,
                "size": 1234,
            }
        ]
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": digest,
            "size": 4096,
        },
        "layers": layers,
    }


def rule_ids(report):
    return {f.rule_id for f in report.findings}


def findings_for(report, rule_id):
    return [f for f in report.findings if f.rule_id == rule_id]


class SecureConfigTest(unittest.TestCase):
    def test_secure_image_has_no_security_findings(self):
        config = make_config()
        report = audit(make_manifest(config), config)
        self.assertEqual(report.findings, [])
        self.assertTrue(report.ok)

    def test_report_sorted_by_severity(self):
        config = make_config()
        config["config"]["User"] = "root"
        config["HostConfig"]["Privileged"] = True
        report = audit(make_manifest(config), config)
        severities = [f.severity for f in report.findings]
        self.assertEqual(severities, sorted(severities, reverse=True))


class RootUserTest(unittest.TestCase):
    def run_user_case(self, user):
        config = make_config()
        config["config"]["User"] = user
        return audit(make_manifest(config), config)

    def test_explicit_root_name(self):
        report = self.run_user_case("root")
        finding = findings_for(report, "root-user")[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.path, "config.config.User")

    def test_uid_zero(self):
        report = self.run_user_case("0")
        self.assertIn("root-user", rule_ids(report))

    def test_uid_zero_with_group(self):
        report = self.run_user_case("0:0")
        self.assertIn("root-user", rule_ids(report))

    def test_missing_user_defaults_to_root(self):
        config = make_config()
        del config["config"]["User"]
        report = audit(make_manifest(config), config)
        self.assertIn("root-user", rule_ids(report))

    def test_nonroot_numeric_user_ok(self):
        report = self.run_user_case("65532")
        self.assertNotIn("root-user", rule_ids(report))


class SocketMountTest(unittest.TestCase):
    def test_docker_socket_bind_is_critical(self):
        config = make_config()
        config["HostConfig"]["Binds"] = [
            "/var/run/docker.sock:/var/run/docker.sock"
        ]
        report = audit(make_manifest(config), config)
        finding = findings_for(report, "sensitive-host-path")[0]
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.path, "config.HostConfig.Binds[0]")

    def test_containerd_socket_mount_object(self):
        config = make_config()
        config["HostConfig"]["Mounts"] = [
            {
                "Type": "bind",
                "Source": "/run/containerd/containerd.sock",
                "Target": "/containerd.sock",
            }
        ]
        report = audit(make_manifest(config), config)
        finding = findings_for(report, "sensitive-host-path")[0]
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.path, "config.HostConfig.Mounts[0].Source")

    def test_host_root_mount_covers_socket(self):
        config = make_config()
        config["HostConfig"]["Binds"] = ["/:/host"]
        report = audit(make_manifest(config), config)
        finding = findings_for(report, "sensitive-host-path")[0]
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_named_volume_not_flagged(self):
        config = make_config()
        config["HostConfig"]["Binds"] = ["data-volume:/data"]
        report = audit(make_manifest(config), config)
        self.assertNotIn("sensitive-host-path", rule_ids(report))


class HostConfigRuleTest(unittest.TestCase):
    def test_privileged(self):
        config = make_config()
        config["HostConfig"]["Privileged"] = True
        report = audit(make_manifest(config), config)
        finding = findings_for(report, "privileged")[0]
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.path, "config.HostConfig.Privileged")

    def test_host_network(self):
        config = make_config()
        config["HostConfig"]["NetworkMode"] = "host"
        report = audit(make_manifest(config), config)
        self.assertIn("host-network", rule_ids(report))

    def test_host_pid(self):
        config = make_config()
        config["HostConfig"]["PidMode"] = "host"
        report = audit(make_manifest(config), config)
        self.assertIn("host-pid", rule_ids(report))

    def test_dangerous_capabilities(self):
        config = make_config()
        config["HostConfig"]["CapAdd"] = ["SYS_ADMIN", "NET_ADMIN", "CHOWN"]
        report = audit(make_manifest(config), config)
        caps = findings_for(report, "dangerous-capability")
        self.assertEqual(len(caps), 2)
        self.assertEqual(caps[0].severity, Severity.CRITICAL)
        self.assertEqual(caps[0].path, "config.HostConfig.CapAdd[0]")
        self.assertEqual(caps[1].severity, Severity.HIGH)

    def test_writable_rootfs_flagged(self):
        config = make_config()
        config["HostConfig"]["ReadonlyRootfs"] = False
        report = audit(make_manifest(config), config)
        finding = findings_for(report, "writable-rootfs")[0]
        self.assertEqual(finding.severity, Severity.LOW)

    def test_missing_readonly_rootfs_flagged(self):
        config = make_config()
        del config["HostConfig"]["ReadonlyRootfs"]
        report = audit(make_manifest(config), config)
        self.assertIn("writable-rootfs", rule_ids(report))


class EnvNameTest(unittest.TestCase):
    def test_suspicious_env_names_flagged_by_name_only(self):
        config = make_config()
        config["config"]["Env"] = [
            "APP_PASSWORD=not-a-real-secret",
            "API_TOKEN=x",
            "HOME=/home/app",
        ]
        report = audit(make_manifest(config), config)
        env_findings = findings_for(report, "suspicious-env-name")
        self.assertEqual(len(env_findings), 2)
        self.assertEqual(env_findings[0].path, "config.config.Env[0]")
        self.assertEqual(env_findings[0].severity, Severity.MEDIUM)

    def test_benign_value_not_flagged(self):
        # Value mentions "secret" but the name does not: must not flag.
        config = make_config()
        config["config"]["Env"] = ["WELCOME_MSG=secret-handshake"]
        report = audit(make_manifest(config), config)
        self.assertNotIn("suspicious-env-name", rule_ids(report))


class DigestVerificationTest(unittest.TestCase):
    def test_matching_digest_passes(self):
        config = make_config()
        report = audit(make_manifest(config), config)
        self.assertNotIn("config-digest-mismatch", rule_ids(report))

    def test_mismatched_digest_is_critical(self):
        config = make_config()
        manifest = make_manifest(config, digest="sha256:" + "0" * 64)
        report = audit(manifest, config)
        finding = findings_for(report, "config-digest-mismatch")[0]
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.path, "manifest.config.digest")

    def test_raw_config_bytes_verified(self):
        config = make_config()
        raw = json.dumps(config, indent=2).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        manifest = make_manifest(config, digest=digest)
        report = audit(manifest, config, config_bytes=raw)
        self.assertNotIn("config-digest-mismatch", rule_ids(report))

    def test_invalid_config_digest_format(self):
        config = make_config()
        manifest = make_manifest(config, digest="not-a-digest")
        report = audit(manifest, config)
        self.assertIn("invalid-digest", rule_ids(report))


class LayerListTest(unittest.TestCase):
    def test_layers_not_a_list(self):
        config = make_config()
        manifest = make_manifest(config, layers="sha256:abc")
        report = audit(manifest, config)
        finding = findings_for(report, "malformed-layers")[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.path, "manifest.layers")

    def test_layer_entry_not_an_object(self):
        config = make_config()
        manifest = make_manifest(config, layers=["sha256:" + "c" * 64])
        report = audit(manifest, config)
        self.assertIn("malformed-layers", rule_ids(report))

    def test_layer_missing_digest(self):
        config = make_config()
        manifest = make_manifest(config, layers=[{"mediaType": "application/vnd.oci.image.layer.v1.tar"}])
        report = audit(manifest, config)
        finding = findings_for(report, "missing-field")[0]
        self.assertEqual(finding.path, "manifest.layers[0].digest")

    def test_layer_digest_bad_format(self):
        config = make_config()
        manifest = make_manifest(config, layers=[{"digest": "sha256:xyz"}])
        report = audit(manifest, config)
        finding = findings_for(report, "invalid-layer-digest")[0]
        self.assertEqual(finding.path, "manifest.layers[0].digest")

    def test_empty_layer_list(self):
        config = make_config()
        manifest = make_manifest(config, layers=[])
        report = audit(manifest, config)
        self.assertIn("malformed-layers", rule_ids(report))

    def test_explicit_layers_argument_overrides_manifest(self):
        config = make_config()
        manifest = make_manifest(config)
        layers = [{"digest": "sha256:" + "d" * 64, "size": 10}]
        report = audit(manifest, config, layers=layers)
        self.assertNotIn("invalid-layer-digest", rule_ids(report))

    def test_diffids_count_mismatch(self):
        config = make_config()
        layers = [
            {"digest": "sha256:" + "e" * 64},
            {"digest": "sha256:" + "f" * 64},
        ]
        report = audit(make_manifest(config, layers=layers), config)
        self.assertIn("diffids-layer-count-mismatch", rule_ids(report))


class DuplicateLabelTest(unittest.TestCase):
    RAW_CONFIG = """{
      "architecture": "amd64",
      "os": "linux",
      "rootfs": {"type": "layers", "diff_ids": ["sha256:%s"]},
      "config": {
        "User": "1000",
        "Labels": {
          "team": "a",
          "team": "b"
        }
      },
      "HostConfig": {"ReadonlyRootfs": true}
    }""" % ("b" * 64,)

    def test_duplicate_label_detected(self):
        config = json.loads(self.RAW_CONFIG)
        digest = "sha256:" + hashlib.sha256(
            self.RAW_CONFIG.encode("utf-8")
        ).hexdigest()
        manifest = make_manifest(config, digest=digest)
        report = audit(manifest, self.RAW_CONFIG)
        finding = findings_for(report, "duplicate-label")[0]
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.path, "config.config.Labels.team")

    def test_parsed_dict_cannot_detect_duplicates(self):
        config = json.loads(self.RAW_CONFIG)
        report = audit(make_manifest(config), config)
        self.assertNotIn("duplicate-label", rule_ids(report))


class MissingFieldTest(unittest.TestCase):
    def test_manifest_missing_config(self):
        config = make_config()
        manifest = make_manifest(config)
        del manifest["config"]
        report = audit(manifest, config)
        paths = {f.path for f in findings_for(report, "missing-field")}
        self.assertIn("manifest.config", paths)

    def test_config_missing_required_fields(self):
        config = make_config()
        del config["architecture"]
        del config["os"]
        del config["rootfs"]["diff_ids"]
        report = audit(make_manifest(config), config)
        paths = {f.path for f in findings_for(report, "missing-field")}
        self.assertIn("config.architecture", paths)
        self.assertIn("config.os", paths)
        self.assertIn("config.rootfs.diff_ids", paths)

    def test_malformed_manifest(self):
        report = audit(["not", "a", "dict"], make_config())
        self.assertIn("malformed-manifest", rule_ids(report))

    def test_malformed_config_json(self):
        manifest = {
            "schemaVersion": 2,
            "config": {"digest": "sha256:" + "0" * 64},
            "layers": [{"digest": LAYER_DIGEST}],
        }
        report = audit(manifest, "{not valid json")
        self.assertIn("malformed-config", rule_ids(report))


if __name__ == "__main__":
    unittest.main()
