# TeamLedger

- [DEV-002 实装、测试与进度 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-002.md)
- [功能规范](https://github.com/r404r/p-research-hr/blob/main/docs/FUNCTIONAL_SPEC.md) · [技术规范](https://github.com/r404r/p-research-hr/blob/main/docs/TECHNICAL_SPEC.md)
- [开发与交付规则](https://github.com/r404r/p-research-hr/blob/main/AGENTS.md)
- [DEV-006 OIDC、会话/MFA、映射维护与 v4 操作者/目标分离实装测试 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-006.md) · [身份协议/时序与实际保护配置/CLI](https://github.com/r404r/p-research-hr/blob/main/docs/TECHNICAL_SPEC.md#71-oidcsession与step-up)
- [DEV-007 当前 R2 组织结构、原子任职/生命周期变更、人员目录/历史、当前精确关系授权与 v5 双库 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-007.md) · [实际 API/production 页面、迁移/授权/隐私与测试证据](https://github.com/r404r/p-research-hr/blob/main/research/hr-implementation/DEV-007-VALIDATION.md)；技术架构图在技术规范 §1.1/§1.2，R2 HTTP 契约 §3.4、原子变更时序 §6.3.1、保护 CLI §9.3。
- [DEV-008 当前 R3 面谈、immutable 三分区版本、独立行动、typed 最小交接与有限导出 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-008.md) · [实际双库/成品与测试证据](https://github.com/r404r/p-research-hr/blob/main/research/hr-implementation/DEV-008-VALIDATION.md)；R3 HTTP 窄契约见技术规范 §3.5、独立批准/版本/导出 Mermaid 时序 §6.4.1、必需独立 `TEAMLEDGER_INTERVIEW_KMS_*` 配置 §9.3。不复用 PII key/credential；API 不自动迁移，生产 IdP/MFA/读者/保留批准另验。
- [DEV-011 评估周期、确定性完成事实与 AI 边界 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-011.md)：R6a 提供 `PUT /api/v1/employees/{employee_id}/interview-policy` 与 `GET /api/v1/employees/{employee_id}/interview-status`、`/employees/{employee_id}/followup` 成品页面及 SQLite/PostgreSQL v9。状态仅来自计划窗口、面谈实际时间、已发布共享笔记与行动项；`periodic_structured_v1` 在 R6a 明确返回 `blocked/automation_not_enabled`，不调用模型或伪装后台自动化。

## Docker 启动

`Dockerfile`生成包含Vue production资源、API、migration及运维命令的单一镜像；`compose.yaml`以SQLite启动`data-init → migrate → api`。API容器以调用者UID/GID运行、root filesystem只读、默认只发布到宿主机`127.0.0.1:8443`。

### 当前依赖边界

当前代码基线是v11，仍要求两个Vault Transit-compatible HTTPS端点（PII、interview）及其CA/token。Docker不会内置测试KMS或伪造生产fallback。DES-007已经批准本地root file＋`teamledger-keyd`的无外部KMS设计，但尚未实装；因此**当前镜像不是完全无外部服务版本**。`TEAMLEDGER_OIDC_MODE=disabled`也只适合隔离评估，真实用户部署必须配置受信OIDC。数据库、Vue/API及容器本身可独立部署，不代表当前身份/KMS/审计边界已独立化。

### 1. 准备环境文件

```bash
cp .env.docker.example .env.docker
```

编辑`.env.docker`：

- `TEAMLEDGER_UID` / `TEAMLEDGER_GID`填写运行Docker的宿主用户`id -u` / `id -g`；保护文件必须归该UID所有。
- `TEAMLEDGER_PUBLIC_ORIGIN`必须等于浏览器实际访问的HTTPS origin。
- 填写PII及interview KMS的HTTPS URL和key name。
- 仅隔离评估可保持`TEAMLEDGER_OIDC_MODE=disabled`；真实部署必须替换为完整OIDC配置。

`.env.docker`已被Git忽略，不得提交。

### 2. 准备保护文件

```bash
install -d -m 0700 docker/secrets
umask 077
openssl rand 32 > docker/secrets/csrf.key
openssl rand 32 > docker/secrets/digest.key
openssl rand 32 > docker/secrets/cursor.key
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout docker/secrets/tls-key.pem \
  -out docker/secrets/tls-cert.pem \
  -days 365 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
```

再放入以下真实部署文件：

| 文件 | 内容 / 权限 |
| --- | --- |
| `kms.token` | PII Transit token；运行UID所有，`0400`或`0600` |
| `kms-ca.pem` | PII Transit CA chain；不得group/other writable |
| `interview-kms.token` | interview Transit独立token；运行UID所有，`0400`或`0600` |
| `interview-kms-ca.pem` | interview Transit独立CA chain；不得group/other writable |
| `tls-key.pem` | API TLS private key；运行UID所有，`0400`或`0600` |
| `tls-cert.pem` | 与`PUBLIC_ORIGIN`匹配的API certificate chain |

执行：

```bash
chown -R "$(id -u):$(id -g)" docker/secrets
chmod 0700 docker/secrets
chmod 0600 docker/secrets/*.key docker/secrets/*.token
chmod 0644 docker/secrets/*.pem
chmod 0600 docker/secrets/tls-key.pem
```

应用会在同一descriptor上校验owner/type/mode；错误owner、symlink、目录或宽松secret权限会拒绝启动。

### 3. 构建并启动

```bash
docker compose --env-file .env.docker config
docker compose --env-file .env.docker up --build -d
docker compose --env-file .env.docker ps
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/live
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/ready
```

`migrate`必须成功退出后API才启动；每次`up`都会安全重跑migration。`live`只证明进程存活，`ready`才包含schema、key及审计积压门禁。查看日志及停止：

```bash
docker compose --env-file .env.docker logs -f api
docker compose --env-file .env.docker down
```

### 持久化数据

Compose默认把SQLite数据库`/var/lib/teamledger/teamledger.db`放入名为`team-ledger-data`的Docker named volume。容器重建、`up --build`及普通`down`均保留该volume。可在`.env.docker`固定另一个稳定名称：

```dotenv
TEAMLEDGER_DATA_VOLUME=team-ledger-production
```

查看和复用：

```bash
docker volume inspect team-ledger-production
docker compose --env-file .env.docker down
docker compose --env-file .env.docker up -d
```

`docker compose down -v`会删除数据库volume，**有持久化数据时不得执行**。`docker/secrets`是独立宿主目录，不在数据库volume或数据库备份内；必须按独立密钥/凭据备份策略保管。复制运行中的SQLite文件不是一致备份；应使用随镜像提供的`/app/teamledger-backup`及对应受控配置。
