# Staff Code 升级维护 · DEV-061

日期：2026-11-10。适用：F-ORG-001 / F-SEC-001 / F-COMP-001 / F-DB-001 的候选 v20。这里只说明经合成数据验证的升级路径；没有在目标部署执行升级。

## 支持范围

| 源应用 / schema | 目标 | 行为 |
| --- | --- | --- |
| `c7475e67af9caf3e7e5ad4929a2fde0d6eac74f8` / 完整 v19 ledger 和结构 | 本次交付 / v20 ready | 一次事务完成 schema 与数据升级 |
| 同一源应用，通用 migrate 已安装 v20 pending | v20 ready | 完成数据升级；pending 时 API 拒绝启动 |
| 同次升级已完成的 v20 ready | v20 ready | 原 apply 快照与 receipt/result snapshot 匹配时幂等返回；漂移拒绝 |
| 其他应用 commit、v1–v18、未知/错 checksum、未知密钥 | 不支持 | 拒绝 apply；不能填假版本强行继续 |

`-source-commit` 是操作者从可信部署记录核对实际镜像 digest 后提供的源 commit，CLI 检查支持列表；数据库本身没有旧镜像来源证明，工具不能代替运维核对。v12–v18 的通用 schema 前向升级支持仍在，但不意味着这些应用被本次工号数据迁移认证。

纯 ASCII 数字不足 6 位左补零；6–10 位不变；超过 10 位拒绝；其他工号保留既有 NFC/UTF-8 规则。所有历史 identifier 和永久 owner 都要覆盖，不能只查当前员工。只输出五项统计（总数、短号、超长数字、归一化工号对、非数字）和保留 owner 数、snapshot、安全 blocker code。归一化工号对包括同员工不同旧值的组合；只有不同员工归属冲突或同员工区间重叠才拒绝。

## 权限和停写

维护操作者需要既有数据库的读权限；apply 另需 DDL、表写及锁权限，PostgreSQL 必须有 TEMP 权限以校验 schema reference。DSN 放在执行 UID 所有、0400/0600 的普通单链接文件中；PG URL 必须 `sslmode=verify-full`，`sslrootcert` 与 `-postgres-ca-file` 相同。不能把 DSN/密码放在命令行或报告中。

PostgreSQL apply 还要求源库和恢复库的维护角色都能读取数据库身份。在这两个 database 中分别由管理员授予最小函数权限（将 `maintenance_role` 换为部署中的维护角色），不需要把维护角色改成 superuser：

```sql
GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO maintenance_role;
```

身份由 `pg_control_system().system_identifier` 与当前 `pg_database.oid` 组成，不使用地址、端口或 `search_path`。同一 database 的其他 schema、主机别名、IPv4/IPv6 或监听地址都不能作为独立恢复库。任一身份查询失败（包括未授权）会在 apply 写入前拒绝；默认 preflight 不要求这项函数权限。

操作者必须停止全部旧/新 API、worker、audit 写入者、定时维护和其他升级进程，锁住部署切流；不允许新旧版本并行。keyd 只在离线导出时停止，完成后独立启动供备份/迁移调用；冻结所有 key rotation。维护 UID 必须在 keyd allowlist，API 不获得 root/keyring 文件权限。`-maintenance-confirmed` 是操作者的停写确认，并非进程探测功能。

Docker 安装包包含 `teamledger-staff-normalize`；Compose 的 `staff-normalize` profile 复用受限维护 UID、数据卷、socket、只读配置和 backup 卷，**不依赖 migrate/API，不自动启动服务**。例如先执行：

```sh
docker compose --env-file .env.docker stop api audit-forwarder audit-receiver
```

其他主机/独立 worker 和维护进程也必须停写。禁止 `down -v`、空库重建、重导员工或覆盖已发布 migration。不要先启动候选 API。

## 备份和独立恢复

以下 shell 变量由操作者指向已准备且权限正确的部署文件/目录。`SOURCE_BIN` 是已核对的 v19 工具目录，`TARGET_BIN` 是本次构建工具目录；`UPGRADE_ROOT`、`SOURCE_KEYS`、`MEDIA_A`、`MEDIA_B`、`ISOLATED_KEYS`、`SOURCE_SOCKET` 和 `RESTORED_SOCKET` 均使用部署内实际的绝对路径。不要在 issue 中粘贴真实路径、密钥或 DSN。两个介质必须不同 filesystem device，祖先目录不能可被其他用户写，输出目录必须独立且为 0700。

先停 keyd 和全部密钥 writer，按现有离线方案导出、验证并恢复（两份 RAW32 media key 各自保护、与归档分开保存）：

```sh
"$SOURCE_BIN/teamledger-keyctl-local" offline-export -key-dir "$SOURCE_KEYS" -archive-a "$MEDIA_A/keys.tlk" -archive-b "$MEDIA_B/keys.tlk" -media-key-a-file "$UPGRADE_ROOT/media-a.key" -media-key-b-file "$UPGRADE_ROOT/media-b.key"
"$SOURCE_BIN/teamledger-keyctl-local" offline-verify-pair -archive-a "$MEDIA_A/keys.tlk" -archive-b "$MEDIA_B/keys.tlk" -media-key-a-file "$UPGRADE_ROOT/media-a.key" -media-key-b-file "$UPGRADE_ROOT/media-b.key"
"$SOURCE_BIN/teamledger-keyctl-local" offline-restore -archive "$MEDIA_A/keys.tlk" -media-key-file "$UPGRADE_ROOT/media-a.key" -target-key-dir "$ISOLATED_KEYS"
```

用部署的进程管理器独立启动源 keyd 和恢复 keyd。恢复实例设置 `TEAMLEDGER_KEYD_DIR=$ISOLATED_KEYS`、独立 `TEAMLEDGER_KEYD_SOCKET=$RESTORED_SOCKET`、相应 `TEAMLEDGER_KEYD_API_UIDS` / `TEAMLEDGER_KEYD_MAINTENANCE_UIDS`；使用 `teamledger-keyd healthcheck` 确认 ready。两实例不得共享 key directory/socket，不把恢复 keyd 接到线上 API。

保持业务停写，用**本次目标版** backup 创建和恢复源数据库（manifest 记录实际 v19/v20，恢复检查与 manifest 版本相同；不要求 pending 库满足 API ready）：

```sh
"$TARGET_BIN/teamledger-backup" -action create -backend sqlite -dsn-file "$UPGRADE_ROOT/source.dsn" -keyd-socket "$SOURCE_SOCKET" -archive "$UPGRADE_ROOT/database.tlb"
"$TARGET_BIN/teamledger-backup" -action restore -backend sqlite -keyd-socket "$RESTORED_SOCKET" -archive "$UPGRADE_ROOT/database.tlb" -target "$UPGRADE_ROOT/restored.db"
```

`restored.dsn` 只包含隔离恢复库路径。PostgreSQL 使用目标版 backup 对应入口，需要该主机受信 `/usr/bin/pg_dump`、`/usr/bin/pg_restore` 与兼容客户端版本；创建与恢复均传受保护 DSN file 和 public CA，不用 SQLite 的 `-target`：

```sh
"$TARGET_BIN/teamledger-backup" -action create -backend postgres -dsn-file "$UPGRADE_ROOT/source.dsn" -postgres-ca-file "$UPGRADE_ROOT/postgres-ca.crt" -keyd-socket "$SOURCE_SOCKET" -archive "$UPGRADE_ROOT/database.tlb"
"$TARGET_BIN/teamledger-backup" -action restore -backend postgres -dsn-file "$UPGRADE_ROOT/restored.dsn" -postgres-ca-file "$UPGRADE_ROOT/postgres-ca.crt" -keyd-socket "$RESTORED_SOCKET" -archive "$UPGRADE_ROOT/database.tlb"
```

恢复目标必须隔离且由原 backup 命令接受，不能覆盖线上库。备份包包含敏感密文，仍按部署备份权限保管。检查源工具恢复结果；本工具再用恢复 keyd 解密恢复库、验证 HMAC、schema/checksum 和完整工号 snapshot。仅勾选“备份完成”不能替代这项实际核验；apply 不接受同一个库或同一个 socket 充当恢复证明。五项工号 preflight 只核对受影响数据，不是整个部署灾备演练认证。

PostgreSQL 恢复目标使用独立 database（可以是同集群的另一个 database）或独立集群；不能仅在源 database 内另建 schema。保留相同 system identifier 和 database OID 的物理复制也不能通过这一独立身份检查。

## 默认 preflight 与显式 apply

停写后运行以下只读 preflight。SQLite 要求文件存在且已是 WAL；不会创建数据库、安装 schema、写业务行或写审计行：

```sh
"$TARGET_BIN/teamledger-staff-normalize" -backend sqlite -dsn-file "$UPGRADE_ROOT/source.dsn" -keyd-socket "$SOURCE_SOCKET" -source-commit c7475e67af9caf3e7e5ad4929a2fde0d6eac74f8
```

将返回的 `snapshot` 复制为 `EXPECTED_SNAPSHOT`。只有退出码 0 且 blockers 为空才可以 apply；request UUID 使用操作者生成的新 UUID，设置为 `UPGRADE_REQUEST_ID`：

```sh
"$TARGET_BIN/teamledger-staff-normalize" -backend sqlite -dsn-file "$UPGRADE_ROOT/source.dsn" -keyd-socket "$SOURCE_SOCKET" -source-commit c7475e67af9caf3e7e5ad4929a2fde0d6eac74f8 -apply -maintenance-confirmed -expected-snapshot "$EXPECTED_SNAPSHOT" -request-id "$UPGRADE_REQUEST_ID" -restored-dsn-file "$UPGRADE_ROOT/restored.dsn" -restored-keyd-socket "$RESTORED_SOCKET"
```

PG 把 `-backend sqlite` 改为 `-backend postgres`，并追加 `-postgres-ca-file "$UPGRADE_ROOT/postgres-ca.crt"`；其他参数相同。Compose 可通过 `docker compose --env-file .env.docker --profile staff-normalize run --rm --no-deps staff-normalize` 后接同样参数执行；路径以容器中的配置/socket/数据卷为准。独立恢复库和 socket 要通过操作者的只读 override 挂载进维护容器，不能把源卷重复挂成恢复卷。主机命令路径不需要 Compose。

拒绝项包括 `invalid_staff_code`、`owner_conflict`、`interval_overlap`、`owner_unverifiable`、`ciphertext_invalid`、`source_lookup_invalid`、`projection_lookup_invalid`、`key_unavailable`；未知 schema/checksum/结构或版本、恢复证明不符、漂移和并发锁失败也返回非零。错误不含工号、员工姓名或凭据。不要自动合并员工、释放旧号或删坏行来“修复”阻断。

## 提交、重试、故障和 postflight

apply 锁定源，复核前一次 snapshot，在一个事务里安装 v20（若需要）、追加规范值密文、永久目标 owner、identifier 投影及不可变无正文 receipt，最后切到 ready。原 identifier、原密文、有效区间、employee ID、change/receipt 引用保持；原号永久归属不删除。相同员工的非重叠历史区间允许规范为同一值。

失败或提交前进程中断会回滚整个事务。源为 v19 时留在 v19；若已单独运行通用 migrate，则留在 v20 pending，继续停写。提交后丢回执可用原参数重试：只有 receipt 的源快照与当前结果快照匹配才幂等返回，不重复插入投影/审计。源状态变化拒绝重试；重新 preflight、备份恢复验证后再决定。没有自动 down migration；成功切流前可用已验证的源 DB/keys 恢复到隔离位置，经人工核对后成对切回旧版本，禁止直接让旧 API 读取 v20。

成功后再运行只读 preflight：五项统计仍覆盖原始历史，因此 `short_numeric` 不会因投影生成而变成 0；`applied` 为 true 只出现在 apply 回执。确认 `CheckSchema` / API 启动 ready、投影及新增 owner 数符合候选数、原历史及 receipt 引用数量保持、不会重复生成迁移 receipt。随后只启动新版本，在合成/受控账号下验证新建/换号、工号显示、短号搜索、Staff 账号关联、人员导入 HOD 和调薪查找；按部署恢复 audit/worker，最后人工开放流量。

有规范化投影后，旧 `staff-reindex` 会在 stage/activate 前拒绝。这一版没有提供投影的 MAC 换键；不要换用旧 binary 绕过检查。密钥仍需保留以解开原历史和备份。没有本次未访问目标环境的现场成功保证。
