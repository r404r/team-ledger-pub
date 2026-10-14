# TeamLedger

- [DEV-002 实装、测试与进度 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-002.md)
- [功能规范](https://github.com/r404r/p-research-hr/blob/main/docs/FUNCTIONAL_SPEC.md) · [技术规范](https://github.com/r404r/p-research-hr/blob/main/docs/TECHNICAL_SPEC.md)
- [开发与交付规则](https://github.com/r404r/p-research-hr/blob/main/AGENTS.md)
- [DEV-018 本地 keyd、受保护根密钥与无外部KMS切换 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-018.md)
- 技术架构图、keyd协议及密钥生命周期：[技术规范 §1.1/§1.2、§7.3/§7.4](https://github.com/r404r/p-research-hr/blob/main/docs/TECHNICAL_SPEC.md)。
## Docker 启动

`Dockerfile`生成Vue production资源、API、migration、`teamledger-keyd`、`audit-receiver`、`audit-forwarder`及运维命令。首次安装显式执行`key-bootstrap`和`audit-bootstrap`；选择内置身份时还须执行一次`identity-bootstrap`。普通启动按`data-init → key-check/migrate → keyd/audit-receiver → audit-forwarder/api`运行，缺少密钥、audit PKI/signer、identity mode或bootstrap事实时直接失败。业务数据库、keyd材料和audit材料使用三个持久volume；API不挂载任何密钥volume。

本地keyd、内置账号/密码、mTLS audit receiver均随同一镜像交付，不依赖云KMS、Vault、外部IdP、外部审计服务、邮件或短信。audit receiver使用现有数据库的专属append-only ledger，不启动第二个数据库。SQLite只能提供独立UID/进程、mTLS和trigger约束，不能抵御API UID、数据库文件持有人或host root篡改；PostgreSQL按`docker/postgres/audit_roles.sql`分离最小角色。另一显式身份值`oidc`要求完整受信`TEAMLEDGER_OIDC_*`配置。

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
sudo install -d -o root -g root -m 0700 docker/audit-maintenance
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
- `TEAMLEDGER_KEYD_UID`、`TEAMLEDGER_MAINTENANCE_UID`、`TEAMLEDGER_AUDIT_RECEIVER_UID`、`TEAMLEDGER_AUDIT_FORWARDER_UID`与API UID必须两两不同；五个进程以共同`TEAMLEDGER_GID`访问获准的socket/SQLite路径，但keyd、API和两个audit进程只挂载各自所需volume；
- `TEAMLEDGER_PUBLIC_ORIGIN`必须等于浏览器实际访问的HTTPS origin；
- `TEAMLEDGER_DATA_VOLUME`、`TEAMLEDGER_KEY_VOLUME`、`TEAMLEDGER_AUDIT_VOLUME`和`TEAMLEDGER_DEPLOYMENT_ID`使用部署唯一、长期稳定的值；
- `TEAMLEDGER_IDENTITY_MODE`必须显式为`local`或`oidc`；`local`同时设置一个稳定的`TEAMLEDGER_BOOTSTRAP_REQUEST_ID`，`oidc`则配置完整`TEAMLEDGER_OIDC_*`；

`.env.docker`已被Git忽略，不得提交。首次安装显式初始化keyd与audit两个材料volume；目标已存在时失败，不覆盖材料。三个one-shot串行执行，避免`compose run`并发重启已完成依赖：

```bash
docker compose --env-file .env.docker build
docker compose --env-file .env.docker --profile bootstrap run --rm key-bootstrap
docker compose --env-file .env.docker --profile bootstrap run --rm audit-bootstrap
docker compose --env-file .env.docker up --abort-on-container-exit --exit-code-from migrate migrate
docker compose --env-file .env.docker up -d --wait keyd audit-receiver
```

`local`模式随后在**空数据库**执行一次身份bootstrap。输入文件必须是maintenance UID拥有的regular、非symlink/非hardlink、`0600` canonical JSON，不能有BOM、空白或末尾换行；密码不得进入argv/env/stdin/log。命令原子创建org、首个subject/account、固定`bootstrap_policy.v1`的OrgR/OrgW/PIIR/PIIW及审计/outbox。相同request UUID和相同文件可安全重试并返回原IDs；不同输入或已有业务事实拒绝：

```bash
docker compose --env-file .env.docker --profile bootstrap run --rm --no-deps identity-bootstrap
```
`key-bootstrap`已先完成data volume初始化；`audit-bootstrap`一次性生成本地CA、receiver/health/forwarder leaf和Ed25519 receipt signer，分别放入受保护子目录。受Compose管理的`migrate`随后完成schema；`up --wait keyd audit-receiver`确认Unix socket和真实mTLS/schema rollback/signer ready。`identity-bootstrap --no-deps`只执行身份事务。

保存命令输出的`org_id`和`subject_id`。后续主体与账号使用maintenance profile中的`/app/teamledger-identity local-subject-create`、`local-account-create`、`local-account-reset`、`local-account-disable`；mode切换仅用`mode-switch`，它会撤销全部会话并推进auth epoch，之后必须以匹配的新mode重启。各账号输入同样使用canonical `{"username":"…","password":"…"}`受保护文件。

此后普通启动的`key-check`只检查三个keyd必需文件存在；keyd启动再验证RAW32长度、认证keyring、16个domain、持久锁及owner/mode/type。audit receiver/forwarder分别验证受保护TLS/signer/trust文件；缺文件、错误owner/mode/type、数据库schema不符或签名能力失败均fail closed，绝不自动生成替代身份。

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

`migrate`成功且keyd、audit receiver健康后API进程启动；forwarder每5秒以同一mTLS身份探测receiver并把单例ready heartbeat写回DB，API `/health/ready`要求heartbeat成功且不超过15秒。forwarder持续claim/retry outbox并仅在验证已持久化receipt后CAS ack。`live`只证明API进程存活；`ready`还包含应用、keyd及既有audit backlog门禁。查看日志及普通停止：

```bash
docker compose --env-file .env.docker logs -f keyd audit-receiver audit-forwarder api
docker compose --env-file .env.docker down
```

### 3. 持久化与重建

默认named volumes：

| 数据 | 容器路径 | 默认volume | 必须独立保管 |
| --- | --- | --- | --- |
| SQLite业务数据、outbox及receiver ledger | `/var/lib/teamledger` | `team-ledger-data` | 是 |
| root/keyring/lock | `/var/lib/teamledger-keys` | `team-ledger-keys` | 是，且不得并入数据库备份 |
| audit CA、leaf、receipt signer/trust | `/var/lib/teamledger-audit` | `team-ledger-audit` | 是，且不得并入数据库备份 |
| keyd Unix socket | `/run/teamledger-keyd` | 临时volume | 否 |

建议生产名称：

```dotenv
TEAMLEDGER_DATA_VOLUME=team-ledger-production-data
TEAMLEDGER_KEY_VOLUME=team-ledger-production-keys
TEAMLEDGER_AUDIT_VOLUME=team-ledger-production-audit
TEAMLEDGER_DEPLOYMENT_ID=teamledger-production
```

普通`down`、容器重建及`up --build`保留三个持久volume：

```bash
docker compose --env-file .env.docker down
docker compose --env-file .env.docker up -d
docker volume inspect team-ledger-production-data
docker volume inspect team-ledger-production-keys
docker volume inspect team-ledger-production-audit
```

`docker compose down -v`会删除业务数据、在线keyd材料和audit身份，存在持久化需求时**不得执行**。丢失audit signer不会自动生成替代key：receiver启动失败；DB中已提交ledger/receipt仍在，但forwarder缺少相应公钥时拒绝ack。keyd和audit材料均须与数据库备份分离保管。

### 3.1 root/keyring双份离线介质

该流程完全本地运行，不调用KMS、Vault、网络或数据库。每次export必须使用两个不同RAW32介质密钥；密钥文件不得放在对应介质上。A/B archive共享同一export UUID和canonical inventory，但分别使用随机nonce认证加密。inventory含root/keyring hash、material generation、全部历史/active/staged key entry及状态、每domain active pointer、源文件metadata、实际离线进程UID/host摘要和每个domain/version的known-answer probe；不含明文key。archive本身不含DB、audit/OIDC私钥或业务备份，因此不能单独恢复服务。

先把A/B挂载为两个独立、由keyd UID拥有且`0700`的可移动文件系统；应用会比较输出父目录的filesystem device ID，相同设备必定拒绝。软件不能证明地理分离，运维仍须确认两个实际介质并分开地点保管。`.env.docker`中的相对路径只是占位，位于同一磁盘时不能export。受保护配置目录及隔离restore父目录同样使用keyd UID。以下命令假设A/B已经分别挂载；生产介质密钥应由独立保管流程生成/解锁：

```bash
set -eu
set -a; . ./.env.docker; set +a
sudo install -d -o "$TEAMLEDGER_KEYD_UID" -g "$TEAMLEDGER_GID" -m 0700 \
  docker/key-offline "$TEAMLEDGER_OFFLINE_RESTORE_DIR"
sudo chown "$TEAMLEDGER_KEYD_UID:$TEAMLEDGER_GID" \
  "$TEAMLEDGER_OFFLINE_MEDIA_A" "$TEAMLEDGER_OFFLINE_MEDIA_B"
sudo chmod 0700 "$TEAMLEDGER_OFFLINE_MEDIA_A" "$TEAMLEDGER_OFFLINE_MEDIA_B"
test "$(stat -c %d "$TEAMLEDGER_OFFLINE_MEDIA_A")" != \
  "$(stat -c %d "$TEAMLEDGER_OFFLINE_MEDIA_B")"
tmp_key_dir="$(mktemp -d "${XDG_RUNTIME_DIR:-$HOME}/teamledger-offline-keys.XXXXXX")"
trap 'rm -rf -- "$tmp_key_dir"' EXIT HUP INT TERM
chmod 0700 "$tmp_key_dir"
(umask 077; openssl rand 32 > "$tmp_key_dir/media-a.key")
(umask 077; openssl rand 32 > "$tmp_key_dir/media-b.key")
sudo install -o "$TEAMLEDGER_KEYD_UID" -g "$TEAMLEDGER_GID" -m 0600 \
  "$tmp_key_dir/media-a.key" docker/key-offline/media-a.key
sudo install -o "$TEAMLEDGER_KEYD_UID" -g "$TEAMLEDGER_GID" -m 0600 \
  "$tmp_key_dir/media-b.key" docker/key-offline/media-b.key
rm -rf -- "$tmp_key_dir"
trap - EXIT HUP INT TERM
```
export前停止整个部署并确认没有key writer；在线keyd仍持有`.lock`时命令必定拒绝。命令从固定descriptor在exclusive OFD lock下取得一个generation snapshot，分别以同目录temp写入、文件/目录`fsync`、`RENAME_NOREPLACE`、父目录`fsync`发布，绝不覆盖同名archive。rename后的提交`fsync`失败会尝试rename回temp并持久化回滚；完整回滚时CLI在stderr返回`status=failed_rolled_back`，回滚rename或持久化失败时返回`status=failed_indeterminate`和`keep_keyd_stopped_and_inspect_requested_paths`动作，不输出路径或密钥。任何失败都必须保持keyd停止，检查并移除本次指定的两个archive路径/restore目标后才可重试，不能把它们登记为有效副本或启动恢复keyd。

```bash
docker compose --env-file .env.docker down
docker compose --env-file .env.docker --profile offline-keys run --rm --no-deps \
  key-offline-export /app/teamledger-keyctl-local offline-export \
  -key-dir /var/lib/teamledger-keys/material \
  -archive-a /media/a/teamledger-keys-2026-10-14.tlk \
  -archive-b /media/b/teamledger-keys-2026-10-14.tlk \
  -media-key-a-file /run/teamledger-key-offline/media-a.key \
  -media-key-b-file /run/teamledger-key-offline/media-b.key \
  -host-identity-file /run/teamledger-host-identity
```

`status=exported_unverified`只表示两份密文已发布，不表示本次副本有效。卸载介质，在隔离主机把A/B分别只读挂载后执行pair verify；verify容器没有在线key volume，且两个介质均为只读挂载。只有返回`status=verified_pair`且export UUID/generation/inventory一致时，才登记该次export并把A/B断电、分开地点保管。任一失败或仅一份成功，整次export作废并销毁孤立archive：

```bash
docker compose --env-file .env.docker --profile offline-keys run --rm --no-deps \
  key-offline-verify /app/teamledger-keyctl-local offline-verify-pair \
  -archive-a /media/a/teamledger-keys-2026-10-14.tlk \
  -archive-b /media/b/teamledger-keys-2026-10-14.tlk \
  -media-key-a-file /run/teamledger-key-offline/media-a.key \
  -media-key-b-file /run/teamledger-key-offline/media-b.key
```

隔离恢复只选一份已验证介质，并只允许不存在的目标目录。命令在同父目录构造完整`root.key`/`keyring.bin`/`.lock`，逐文件及目录`fsync`后以`RENAME_NOREPLACE`原子安装；现存目标、错密钥、AEAD/sidecar/hash/state/pointer/probe不符均拒绝。随后以恢复目录启动真实keyd做ready probe，但不得直接替换线上volume：

```bash
docker compose --env-file .env.docker --profile offline-keys run --rm --no-deps \
  key-offline-verify /app/teamledger-keyctl-local offline-restore \
  -archive /media/a/teamledger-keys-2026-10-14.tlk \
  -media-key-file /run/teamledger-key-offline/media-a.key \
  -target-key-dir /restore/teamledger-keys
```

如同时恢复数据库，另用既有隔离restore核对`crypto_control` generation、keyring digest、active pointers、A1/A2 ack及全部wrapper/MAC历史依赖；任何不匹配都不得ready或猜测新key。介质采购、远程保管、自动解锁、切流、RPO/RTO/PITR不在当前范围。

### 4. Audit材料轮换与PostgreSQL角色

所有命令必须在停止receiver/forwarder writer后，以root运行同一`audit-bootstrap`镜像并传入与`.env.docker`一致的UID/GID。`rotate-leaves`沿用当前CA；`rotate-ca`先发布新旧双CA trust、再切换双方leaf，实际确认mTLS后才可`retire-ca`。中断时保持服务停止并重跑同一命令。signer轮换先向forwarder trust发布新旧双key，再激活新private。重启并实际确认投递后仍须保留旧公钥，直到不存在使用该`key_id`的未ack重放以及依赖旧receipt的保留备份；旧私钥不会保留，已提交事件重放使用ledger内原receipt bytes。
先加载非秘密的本地部署变量，并记录轮换前`signer-id`。以下是leaf与signer轮换：

```bash
set -a; . ./.env.docker; set +a
docker compose --env-file .env.docker --profile bootstrap run --rm --no-deps \
  audit-bootstrap /app/teamledger-audit-bootstrap signer-id -dir /var/lib/teamledger-audit/material \
  -receiver-uid "$TEAMLEDGER_AUDIT_RECEIVER_UID" \
  -forwarder-uid "$TEAMLEDGER_AUDIT_FORWARDER_UID" -gid "$TEAMLEDGER_GID"
docker compose --env-file .env.docker stop audit-forwarder audit-receiver
docker compose --env-file .env.docker --profile bootstrap run --rm --no-deps \
  audit-bootstrap /app/teamledger-audit-bootstrap rotate-leaves -dir /var/lib/teamledger-audit/material \
  -receiver-name audit-receiver -bootstrap-uid 0 \
  -receiver-uid "$TEAMLEDGER_AUDIT_RECEIVER_UID" \
  -forwarder-uid "$TEAMLEDGER_AUDIT_FORWARDER_UID" -gid "$TEAMLEDGER_GID"
docker compose --env-file .env.docker --profile bootstrap run --rm --no-deps \
  audit-bootstrap /app/teamledger-audit-bootstrap rotate-signer -dir /var/lib/teamledger-audit/material \
  -receiver-uid "$TEAMLEDGER_AUDIT_RECEIVER_UID" \
  -forwarder-uid "$TEAMLEDGER_AUDIT_FORWARDER_UID" -gid "$TEAMLEDGER_GID"
docker compose --env-file .env.docker up -d --wait audit-receiver audit-forwarder
# 仅在未ack重放已由命令实时查库为零，且保留备份已核对不再依赖旧key_id后退役旧公钥：
docker compose --env-file .env.docker --profile bootstrap run --rm --no-deps \
  audit-bootstrap /app/teamledger-audit-bootstrap retire-signer -dir /var/lib/teamledger-audit/material \
  -receiver-uid "$TEAMLEDGER_AUDIT_RECEIVER_UID" \
  -forwarder-uid "$TEAMLEDGER_AUDIT_FORWARDER_UID" -gid "$TEAMLEDGER_GID" \
  -key-id receipt-OLD -confirm-no-backup-dependencies
```

`retire-signer`必须连接当前业务DB并确认该`key_id`关联的pending/inflight outbox为零；DB不可达或仍有未ack receipt即拒绝。`-confirm-no-backup-dependencies`是运维者完成保留备份清单核对后的显式断言，不能用来跳过实时DB检查。
PostgreSQL部署使用`teamledger_audit_maintainer`，不得把含凭据DSN写入`.env.docker`或argv：以root `0600`、regular、单link且无末尾换行的文件保存到`docker/audit-maintenance/postgres-dsn`，CA保存为同目录`postgres-ca.pem`；再设置以下非秘密路径配置。Compose只读挂载该专用目录，CLI同时拒绝DSN环境值与文件值并存：

```dotenv
TEAMLEDGER_AUDIT_MAINTENANCE_DB_BACKEND=postgres
TEAMLEDGER_AUDIT_MAINTENANCE_DB_DSN=
TEAMLEDGER_AUDIT_MAINTENANCE_DB_DSN_FILE=/run/teamledger-audit-maintenance/postgres-dsn
TEAMLEDGER_AUDIT_MAINTENANCE_DB_CA_FILE=/run/teamledger-audit-maintenance/postgres-ca.pem
```

CA轮换是单独的双trust切换，不与上述`rotate-leaves`同时执行：

```bash
docker compose --env-file .env.docker stop audit-forwarder audit-receiver
docker compose --env-file .env.docker --profile bootstrap run --rm --no-deps \
  audit-bootstrap /app/teamledger-audit-bootstrap rotate-ca -dir /var/lib/teamledger-audit/material \
  -receiver-name audit-receiver -bootstrap-uid 0 \
  -receiver-uid "$TEAMLEDGER_AUDIT_RECEIVER_UID" \
  -forwarder-uid "$TEAMLEDGER_AUDIT_FORWARDER_UID" -gid "$TEAMLEDGER_GID"
docker compose --env-file .env.docker up -d --wait audit-receiver audit-forwarder
# 实际产生并确认一条新audit receipt后，才停止双方并退役旧CA：
docker compose --env-file .env.docker stop audit-forwarder audit-receiver
docker compose --env-file .env.docker --profile bootstrap run --rm --no-deps \
  audit-bootstrap /app/teamledger-audit-bootstrap retire-ca -dir /var/lib/teamledger-audit/material \
  -bootstrap-uid 0 -receiver-uid "$TEAMLEDGER_AUDIT_RECEIVER_UID" \
  -forwarder-uid "$TEAMLEDGER_AUDIT_FORWARDER_UID" -gid "$TEAMLEDGER_GID"
docker compose --env-file .env.docker up -d --wait audit-receiver audit-forwarder
```

Compose默认SQLite，不承诺数据库角色隔离。PostgreSQL部署由v12 schema owner执行`docker/postgres/audit_roles.sql`，再由部署系统为四个NOLOGIN角色配置本地LOGIN凭据/成员关系和强制TLS；runtime不得使用schema owner。receiver只获`schema_version`和receiver chain/ledger所需权限，forwarder获`audit_event/audit_outbox`读取、outbox更新及receiver status heartbeat写入，离线maintainer只获ledger/outbox SELECT，API login只继承`teamledger_audit_api_status`以读取heartbeat；任何runtime角色均不得UPDATE/DELETE ledger。

### 5. 备份与恢复

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

### 6. 包装密钥轮换

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

### 7. MAC索引与CSRF轮换

MAC domain必须先用上节同一`keyctl-local stage`及批准manifest建立唯一staged generation。之后按domain运行唯一维护入口；命令从加密canonical source重算全部行，核对集合数量，在keyd activate后以旧digest CAS切换索引，再完成A2/DB/keyd ack。维护期间keyd关闭新MAC写；命令可用同一manifest安全重跑。不得用通用`activate`跳过数据库重建。

```bash
# Staff Code 全量索引
docker compose --env-file .env.docker --profile maintenance run --rm maintenance \
  /app/teamledger-staff-reindex \
  -backend sqlite -dsn-file /run/teamledger-maintenance/sqlite-dsn \
  -keyd-socket /run/teamledger-keyd/keyd.sock \
  -manifest-file /run/teamledger-maintenance/staff-code-rotation.json

# OIDC issuer/sub；local username 使用 -domain local_username
docker compose --env-file .env.docker --profile maintenance run --rm maintenance \
  /app/teamledger-identity reindex \
  -domain oidc -backend sqlite \
  -dsn-file /run/teamledger-maintenance/sqlite-dsn \
  -keyd-socket /run/teamledger-keyd/keyd.sock \
  -manifest-file /run/teamledger-maintenance/identity-rotation.json

# CSRF：先在一个事务撤销旧version全部live session并推进epoch，再activate
docker compose --env-file .env.docker --profile maintenance run --rm maintenance \
  /app/teamledger-keyctl-local csrf-activate \
  -backend sqlite -dsn-file /run/teamledger-maintenance/sqlite-dsn \
  -socket /run/teamledger-keyd/keyd.sock \
  -manifest-file /run/teamledger-maintenance/csrf-rotation.json \
  -request-id 01234567-89ab-4cde-8f01-23456789abcd
```

`identity_subject_lookup`、`local_username_lookup`、`staff_code_lookup`和`csrf_token`须分别stage，不得共用manifest或目标key。OIDC source是AAD绑定mapping/org/subject的`identity.mapping.v1`密文；local username和Staff Code也只从各自受保护source重建。source缺失、集合漂移、错误manifest、目标key/version不一致或任一CAS失败均保持不可写，不做部分切换。所有持久MAC事实保存exact key ID/version。`command_receipt`、`assessment_generation`当前没有安全到期/全量重建policy，`local_password_pepper`当前没有credential dependency maintenance入口；`teamledger-keyctl-local`拒绝这三个domain的generic stage/activate，不能以通用命令绕过。cursor最长15分钟；cursor key变化只令旧cursor安全失效。历史password pepper仍按credential的exact reference验证，成功登录后惰性升级。
