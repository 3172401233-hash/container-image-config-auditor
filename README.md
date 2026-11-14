# container-image-config-auditor
Python OCI 镜像配置审计库，检查 root 用户、capabilities、敏感挂载和启动参数

纯元数据审计：输入 manifest、image config 和层清单（均为解析后的 JSON），不启动容器。

## 用法

```python
from oci_auditor import audit

report = audit(manifest, config, layers=None, config_bytes=None)
for finding in report.findings:      # 已按严重度降序排列
    print(finding.severity.label, finding.rule_id, finding.path, finding.message)
```

- `manifest`：解析后的 OCI image manifest（dict）
- `config`：解析后的 image config（dict），或原始 JSON 文本/字节（原始输入可检测重复标签）
- `layers`：层描述符列表，缺省取 `manifest["layers"]`
- `config_bytes`：config 原始字节，用于校验 `manifest.config.digest`；缺省时对 dict 做规范化序列化后计算

## 检查项

安全规则（路径前缀 `config.` 表示 image config 文档）：

- `root-user`：`config.config.User` 为空、`root` 或 uid 0（HIGH）
- `writable-rootfs`：`config.HostConfig.ReadonlyRootfs` 非 true（LOW）
- `privileged` / `host-network` / `host-pid` / `host-ipc`：HostConfig 中的运行时配置（CRITICAL/HIGH/HIGH/MEDIUM）
- `dangerous-capability`：`CapAdd` 中的危险 capability，`ALL`/`SYS_ADMIN` 为 CRITICAL
- `sensitive-host-path`：`Binds`/`Mounts` 挂载 docker.sock、containerd.sock 等敏感主机路径（CRITICAL/HIGH）
- `suspicious-env-name`：仅按变量名匹配（PASSWORD/SECRET/TOKEN/API_KEY 等），不解析变量值（MEDIUM）

结构校验（路径前缀 `manifest.` 或 `config.`）：

- `config-digest-mismatch`：config blob 哈希与 `manifest.config.digest` 不一致（CRITICAL）
- `invalid-digest` / `invalid-layer-digest`：digest 不符合 OCI 格式（HIGH）
- `malformed-layers`：层列表不是数组、元素不是对象或为空（HIGH/MEDIUM）
- `missing-field`：manifest/config/rootfs/层描述符缺失必需字段（HIGH）
- `duplicate-label`：Labels 中重复的键（需传入原始 JSON 文本，MEDIUM）
- `diffids-layer-count-mismatch`：`rootfs.diff_ids` 数量与层数不一致（MEDIUM）

## 测试

```
python -m unittest
```
