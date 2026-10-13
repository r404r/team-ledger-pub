# TeamLedger

- [DEV-002 实装、测试与进度 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-002.md)
- [功能规范](https://github.com/r404r/p-research-hr/blob/main/docs/FUNCTIONAL_SPEC.md) · [技术规范](https://github.com/r404r/p-research-hr/blob/main/docs/TECHNICAL_SPEC.md)
- [开发与交付规则](https://github.com/r404r/p-research-hr/blob/main/AGENTS.md)
- [DEV-018 本地 keyd、受保护根密钥与无外部KMS切换 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-018.md)
- 技术架构图、keyd协议及密钥生命周期：[技术规范 §1.1/§1.2、§7.3/§7.4](https://github.com/r404r/p-research-hr/blob/main/docs/TECHNICAL_SPEC.md)。
## Docker 启动

`Dockerfile`生成Vue production资源、API、migration、`teamledger-keyd`、`keyctl-local`及运维命令。首次安装显式执行`key-bootstrap`；选择内置身份时还须执行一次`identity-bootstrap`。普通启动按`data-init → key-check → keyd/migrate → api`运行，缺少密钥材料、身份mode或bootstrap事实时直接失败。数据库和密钥分别存放；API不挂载根密钥卷，只通过Unix socket调用本地keyd。

本地keyd及`TEAMLEDGER_IDENTITY_MODE=local`内置账号/密码均随同一镜像交付，不依赖云KMS、Vault、外部IdP、邮件或短信。另一显式值`oidc`要求完整受信`TEAMLEDGER_OIDC_*`配置。两种模式互斥；没有`disabled`、自动fallback或账号自动合并。

### 1. 准备环境与TLS文件

```bash
cp .env.docker.example .env.docker
install -d -m 0700 docker/secrets
umask 077
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout docker/secrets/tls-key.pem \
  -out docker/secrets/tls-cert.pem \
  -days 365 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
chown -R "$(id -u):$(id -g)" docker/secrets
chmod 0700 docker/secrets
chmod 0600 docker/secrets/tls-key.pem
chmod 0644 docker/secrets/tls-cert.pem
install -d -o "$(id -u)" -g "$(id -g)" -m 0750 docker/maintenance
install -d -o "$(id -u)" -g "$(id -g)" -m 0770 backups
printf '%s\n' /var/lib/teamledger/teamledger.db > docker/maintenance/sqlite-dsn
sudo chown 10002:"$(id -g)" docker/maintenance/sqlite-dsn # 10002须等于TEAMLEDGER_MAINTENANCE_UID
sudo chmod 0600 docker/maintenance/sqlite-dsn
install -m 0600 /dev/null docker/maintenance/local-bootstrap.json
# 使用不会追加换行的受保护编辑器写入且仅写入：
# {"timezone":"Asia/Shanghai","username":"admin.user","password":"至少12字节的初始密码"}
sudo chown 10002:"$(id -g)" docker/maintenance/local-bootstrap.json
```

在`.env.docker`中：

- `TEAMLEDGER_UID` / `TEAMLEDGER_GID`填写API使用的主机`id -u` / `id -g`；
- `TEAMLEDGER_KEYD_UID`和`TEAMLEDGER_MAINTENANCE_UID`必须是两个不同于API UID、且彼此不同的专用数值UID；API、keyd、maintenance以共同`TEAMLEDGER_GID`访问socket，API和maintenance也以该组访问SQLite数据卷；keyd不挂载数据卷，API不挂载key卷；
- `TEAMLEDGER_PUBLIC_ORIGIN`必须等于浏览器实际访问的HTTPS origin；
- `TEAMLEDGER_DATA_VOLUME`和`TEAMLEDGER_KEY_VOLUME`使用部署唯一、长期稳定的volume名称；
- `TEAMLEDGER_IDENTITY_MODE`必须显式为`local`或`oidc`；`local`同时设置一个稳定的`TEAMLEDGER_BOOTSTRAP_REQUEST_ID`，`oidc`则配置完整`TEAMLEDGER_OIDC_*`；

`.env.docker`已被Git忽略，不得提交。首次安装先显式初始化一次密钥volume；目标已存在时失败，不覆盖材料：

```bash
docker compose --env-file .env.docker build
docker compose --env-file .env.docker --profile bootstrap run --rm key-bootstrap
docker compose --env-file .env.docker up --abort-on-container-exit --exit-code-from migrate migrate
docker compose --env-file .env.docker up -d --wait keyd
```

`local`模式随后在**空数据库**执行一次身份bootstrap。输入文件必须是maintenance UID拥有的regular、非symlink/非hardlink、`0600` canonical JSON，不能有BOM、空白或末尾换行；密码不得进入argv/env/stdin/log。命令原子创建org、首个subject/account、固定`bootstrap_policy.v1`的OrgR/OrgW/PIIR/PIIW及审计/outbox。相同request UUID和相同文件可安全重试并返回原IDs；不同输入或已有业务事实拒绝：

```bash
docker compose --env-file .env.docker --profile bootstrap run --rm --no-deps identity-bootstrap
```
`key-bootstrap`已先完成data volume初始化；受Compose管理的`migrate`服务随后完成schema并以其退出码作为门禁，`up --wait keyd`再确认共享socket已对后续容器可用；`identity-bootstrap --no-deps`只执行身份事务，不让`compose run`并发重启已完成的one-shot依赖。

保存命令输出的`org_id`和`subject_id`。后续主体与账号使用maintenance profile中的`/app/teamledger-identity local-subject-create`、`local-account-create`、`local-account-reset`、`local-account-disable`；mode切换仅用`mode-switch`，它会撤销全部会话并推进auth epoch，之后必须以匹配的新mode重启。各账号输入同样使用canonical `{"username":"…","password":"…"}`受保护文件。

此后普通启动的`key-check`只检查三个必需文件存在；keyd启动再验证RAW32长度、认证keyring、16个domain、持久锁及owner/mode/type。密钥volume为空、身份bootstrap缺失、挂载错误或材料校验失败时启动失败，绝不在启动路径中创建或修复密钥。

### 2. 构建、启动与健康检查

```bash
docker compose --env-file .env.docker config
docker compose --env-file .env.docker up -d
docker compose --env-file .env.docker ps
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/live
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/ready
```

`migrate`成功且keyd健康后API才启动。`live`只证明进程存活；`ready`包含应用就绪门禁。查看日志及普通停止：

```bash
docker compose --env-file .env.docker logs -f keyd api
docker compose --env-file .env.docker down
```

### 3. 持久化与重建

默认named volumes：

| 数据 | 容器路径 | 默认volume | 必须独立保管 |
| --- | --- | --- | --- |
| SQLite业务数据 | `/var/lib/teamledger` | `team-ledger-data` | 是 |
| root/keyring/lock | `/var/lib/teamledger-keys` | `team-ledger-keys` | 是，且不得并入数据库备份 |
| keyd Unix socket | `/run/teamledger-keyd` | 临时volume | 否 |

建议生产名称：

```dotenv
TEAMLEDGER_DATA_VOLUME=team-ledger-production-data
TEAMLEDGER_KEY_VOLUME=team-ledger-production-keys
```

普通`down`、容器重建及`up --build`保留两个持久volume：

```bash
docker compose --env-file .env.docker down
docker compose --env-file .env.docker up -d
docker volume inspect team-ledger-production-data
docker volume inspect team-ledger-production-keys
```

`docker compose down -v`会删除业务数据和唯一在线密钥材料，存在持久化需求时**不得执行**。丢失密钥volume后，数据库内敏感数据及keyd包装的备份无法恢复。离线根密钥副本必须与数据库备份分离保管。

### 4. 备份与恢复

`teamledger-backup`每次创建随机archive DEK，并通过maintenance UID可访问的本地keyd `backup_archive` domain包装；没有长期`backup-key-file`。备份文件不含root/keyring。Compose的profile限定`maintenance`服务使用独立maintenance UID，挂载SQLite数据卷、keyd socket、`docker/maintenance`只读配置及`TEAMLEDGER_BACKUP_DIR`归档目录；API UID不能替代它。

```bash
docker compose --env-file .env.docker --profile maintenance run --rm maintenance \
  /app/teamledger-backup \
  -action create -backend sqlite \
  -dsn-file /run/teamledger-maintenance/sqlite-dsn \
  -archive /backup/teamledger-$(date +%F).tlb \
  -keyd-socket /run/teamledger-keyd/keyd.sock

docker compose --env-file .env.docker --profile maintenance run --rm maintenance \
  /app/teamledger-backup \
  -action restore -backend sqlite \
  -archive /backup/teamledger-2026-10-14.tlb \
  -target /backup/restored-teamledger.db \
  -keyd-socket /run/teamledger-keyd/keyd.sock
```

`sqlite-dsn`必须由`TEAMLEDGER_MAINTENANCE_UID`拥有、权限`0600`，内容为容器内SQLite绝对路径；上例的`10002`须随`.env.docker`同步。恢复只写隔离的`/backup/restored-teamledger.db`，先通过keyd解包archive DEK，再验证archive认证、schema和数据库内包装密钥样本；命令不会替换在线数据库。keyd或所需历史key缺失时不会产生可切流目标；复制运行中的SQLite文件不是一致备份。

每个archive头部记录包装DEK所依赖的`backup_archive` key ID/version；数据库内manifest另列`pii`、`interview`、`assessment`、`financial`全部包装依赖。当前`backup_archive`历史key禁止退役：在尚无外部保留archive清单协议时，保留旧key优先于误删后令离线archive永久不可恢复。

### 5. 包装密钥轮换

先离线生成目标key UUID和下一版本，按`key-rewrap` canonical approval格式签名完整approval JSON，并把approval及真实Ed25519批准者注册表`key-rewrap-approval-authorities.json`放入`docker/maintenance`。approval必须由maintenance UID拥有且为`0600`；批准者注册表是固定trust root，必须由root拥有且不可组/其他用户写（建议`0444`）。keyd只生成key material，目标ID/版本必须与已签approval一致。普通流程只由`keyctl-local stage`建立A1 candidate，再由`teamledger-key-rewrap`完成数据库A1、分批rewrap、activate A2、DB/keyd ack及无引用旧key退役；不要在正常流程中手工调用`activate`。

```bash
sudo chown 10002:"$(id -g)" docker/maintenance/financial-rewrap-approval.json
sudo chmod 0600 docker/maintenance/financial-rewrap-approval.json
sudo chown 0:0 docker/maintenance/key-rewrap-approval-authorities.json
sudo chmod 0444 docker/maintenance/key-rewrap-approval-authorities.json
```

上例`10002`同样须等于`TEAMLEDGER_MAINTENANCE_UID`。

```bash
docker compose --env-file .env.docker --profile maintenance run --rm maintenance \
  /app/teamledger-keyctl-local stage \
  -socket /run/teamledger-keyd/keyd.sock \
  -domain financial \
  -target-key-id 01234567-89ab-4cde-8f01-23456789abcd \
  -target-version 2 \
  -manifest-file /run/teamledger-maintenance/financial-rewrap-approval.json

docker compose --env-file .env.docker --profile maintenance run --rm maintenance \
  /app/teamledger-key-rewrap \
  -backend sqlite \
  -dsn-file /run/teamledger-maintenance/sqlite-dsn \
  -keyd-socket /run/teamledger-keyd/keyd.sock \
  -approval-file /run/teamledger-maintenance/financial-rewrap-approval.json \
  -limit 500
```

approval的`target_kek_id`、`target_version`必须分别等于stage参数；`keyctl-local`和`key-rewrap`对同一文件计算SHA-256 manifest。未完成DB ack时API除`/health/live`外返回503，keyd拒绝新wrap/MAC。命令可用同一approval重复执行以恢复stage、rewrap、activate、ack或retire之间的中断；任一数据库仍引用旧包装key时不会退役。
