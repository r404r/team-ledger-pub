# TeamLedger

- [公开文档索引](docs/README.md)
- [功能规范](docs/FUNCTIONAL_SPEC.md) · [技术规范](docs/TECHNICAL_SPEC.md)
- [开发与交付规则](docs/DEVELOPMENT_RULES.md)
- 技术架构图、keyd协议及密钥生命周期：[技术规范 §1.1/§1.2、§7.3/§7.4](docs/TECHNICAL_SPEC.md#1-架构部署与信任边界)。
- Public文档归并范围及验证：[DEV-024 PLAN](docs/plans/DEV-024.md)。

## Docker 安装与运维

### 1. 首次安装：Linux / Windows 初学者路线

本节从一台尚未安装TeamLedger的电脑开始，最终得到：

- 浏览器可访问的 `https://localhost:8443`；
- 一个内置管理员账号；
- 保存在Docker named volume中的SQLite业务数据、本地keyd材料和audit材料；
- 不依赖外部KMS、Vault、OIDC IdP或审计服务的本机部署。

此路线只适合操作者所在电脑的本机安装。默认只监听`127.0.0.1`，TLS证书也只覆盖`localhost`/`127.0.0.1`，其他内网设备不能访问。内网多机或公网部署必须另行配置受信证书、实际hostname、监听/防火墙和`TEAMLEDGER_PUBLIC_ORIGIN`，不能直接照搬本节的自签名证书。初次安装先不要改用OIDC、PostgreSQL、反向代理或自定义域名；完成本节并确认服务正常后，再按后续高级章节调整。

#### 1.1 选择操作系统路径

**Linux**

1. 安装Docker Engine、Docker Compose plugin、Git、OpenSSL和curl。Docker安装以[官方Docker Engine文档](https://docs.docker.com/engine/install/)为准。
2. 确保当前用户能运行Docker。若必须在每条Docker命令前使用`sudo`，可以照做，但后续创建文件的普通命令仍以当前用户执行。
3. 打开Terminal，执行：

```bash
docker --version
docker compose version
git --version
openssl version
curl --version
docker run --rm hello-world
```

五条版本命令和`hello-world`都成功后继续。必须使用带空格的`docker compose`（Compose v2），不是旧的`docker-compose`。

**Windows 10/11**

1. 在BIOS/UEFI启用CPU virtualization。以管理员身份打开Windows Terminal或PowerShell，按[Microsoft WSL安装文档](https://learn.microsoft.com/windows/wsl/install)执行：

```powershell
wsl --install -d Ubuntu
```

2. 按提示重启Windows；从开始菜单打开Ubuntu，等待初始化并创建Linux用户名和密码。该密码用于后续`sudo`。
3. 安装[Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/)，选择WSL 2 backend和Linux containers。
4. 打开Docker Desktop的 **Settings → Resources → WSL Integration**，启用Ubuntu并点击 **Apply & restart**。
5. 打开Windows Terminal中的Ubuntu窗口；不要在PowerShell/CMD执行后续Linux命令。安装工具并验证Docker Desktop连接：

```bash
sudo apt update
sudo apt install -y git openssl curl
docker --version
docker compose version
git --version
openssl version
curl --version
docker run --rm hello-world
```

6. 上述命令全部成功后继续。后续**全部命令都在同一个Ubuntu WSL窗口执行**。仓库必须位于例如`~/team-ledger`的WSL Linux filesystem；不要放在`C:\...`、`/mnt/c/...`、OneDrive或Windows网络盘。TeamLedger会严格检查密钥及bootstrap文件的Linux owner/mode，Windows filesystem bind mount不能可靠提供这些属性。

#### 1.2 下载TeamLedger

在Linux Terminal或Windows的Ubuntu WSL窗口执行：

```bash
cd ~
git clone https://github.com/r404r/team-ledger-pub.git
cd team-ledger-pub
```

若已经clone，进入该目录即可。以下所有命令都必须在包含`compose.yaml`的`team-ledger`目录执行。确认位置和文件：

```bash
pwd
test -f compose.yaml && test -f .env.docker.example && echo "source OK"
```

看到`source OK`才继续。

#### 1.3 生成本机配置、TLS证书和初始管理员文件

复制配置，并自动写入当前Linux/WSL用户的UID、GID和一次性bootstrap request ID：

```bash
cp .env.docker.example .env.docker
sed -i \
  -e "s/^TEAMLEDGER_UID=.*/TEAMLEDGER_UID=$(id -u)/" \
  -e "s/^TEAMLEDGER_GID=.*/TEAMLEDGER_GID=$(id -g)/" \
  -e "s/^TEAMLEDGER_BOOTSTRAP_REQUEST_ID=.*/TEAMLEDGER_BOOTSTRAP_REQUEST_ID=$(cat /proc/sys/kernel/random/uuid)/" \
  .env.docker
. ./.env.docker
```

默认配置使用：

- 身份模式：`local`；
- 地址：`https://localhost:8443`；
- 数据卷：`team-ledger-data`；
- key卷：`team-ledger-keys`；
- audit卷：`team-ledger-audit`。

这些volume名称和`TEAMLEDGER_DEPLOYMENT_ID`在安装后必须保持稳定。多套安装必须为每套使用不同名称和端口。

生成localhost自签名证书和受保护目录：

```bash
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
sudo chown "$TEAMLEDGER_MAINTENANCE_UID:$TEAMLEDGER_GID" docker/maintenance/sqlite-dsn
sudo chmod 0600 docker/maintenance/sqlite-dsn
```

生成初始管理员`admin.user`的随机密码和严格canonical JSON。命令会显示密码一次；立即保存到密码管理器，不要截图、发送或提交到Git：

```bash
bootstrap_password="$(openssl rand -base64 24 | tr -d '\n')"
printf '%s' \
  "{\"timezone\":\"Asia/Shanghai\",\"username\":\"admin.user\",\"password\":\"$bootstrap_password\"}" \
  > docker/maintenance/local-bootstrap.json
sudo chown "$TEAMLEDGER_MAINTENANCE_UID:$TEAMLEDGER_GID" \
  docker/maintenance/local-bootstrap.json
sudo chmod 0600 docker/maintenance/local-bootstrap.json
printf 'Initial username: admin.user\nInitial password: %s\n' "$bootstrap_password"
unset bootstrap_password
```

`local-bootstrap.json`不能有BOM、前后空白或末尾换行，也不能是symlink/hardlink。上述命令已满足这些要求。`.env.docker`、证书私钥和bootstrap文件已由`.gitignore`排除，但仍属于敏感文件。

#### 1.4 只在首次安装执行bootstrap

严格按顺序逐条执行；上一条成功退出后再执行下一条：

```bash
docker compose --env-file .env.docker config --quiet
docker compose --env-file .env.docker build
docker compose --env-file .env.docker --profile bootstrap run --rm key-bootstrap
docker compose --env-file .env.docker --profile bootstrap run --rm audit-bootstrap
docker compose --env-file .env.docker up \
  --abort-on-container-exit --exit-code-from migrate migrate
docker compose --env-file .env.docker up -d --wait keyd audit-receiver
docker compose --env-file .env.docker --profile bootstrap run \
  --rm --no-deps identity-bootstrap
```

成功标准：

1. `config --quiet`没有输出且exit code为0；
2. image build结束时没有`ERROR`；
3. key bootstrap显示`key directory initialized`；
4. audit bootstrap成功退出；
5. migrate成功退出；
6. keyd和audit receiver显示healthy；
7. identity bootstrap显示包含`org_id`和`subject_id`的结果。

保存`org_id`和`subject_id`，用于后续账号及权限维护；确认密码已保存后删除含明文初始密码的bootstrap输入：

```bash
rm -f docker/maintenance/local-bootstrap.json
```

三个bootstrap命令是初始化命令，不是普通启动命令；成功后不要再次执行。某一步失败时先诊断该步骤，只从失败步骤继续，不要重跑此前成功的key/audit bootstrap。相同identity request和相同输入可以安全重试，但不同输入或已有业务事实会被拒绝。

#### 1.5 启动全部服务并确认可用

```bash
docker compose --env-file .env.docker up -d --wait
docker compose --env-file .env.docker ps
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/live
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/ready
```

`ps`中长期服务应为`Up`/`healthy`，两个curl命令都应成功。浏览器打开：

```text
https://localhost:8443
```

使用`admin.user`及刚才保存的初始密码登录。fresh安装必须依次完成“首次改密 → 重新登录 → TOTP登记”，在此之前不会开放员工、授权、审计或用户管理：

1. 在“修改初始密码”输入刚才的初始密码和一个不同的新密码。成功后当前受限会话立即失效；旧初始密码不再可用。
2. 使用`admin.user`和新密码重新登录。此时只会进入“设置 TOTP 验证器”受限页面。
3. 在手机或其他独立设备安装任一支持标准TOTP的离线Authenticator；TeamLedger不要求连接外部MFA服务。
4. 扫描页面二维码；不能扫描时，手工输入页面显示的Base32密钥，再输入当前6位验证码并启用。
5. 页面随后只显示一次账号恢复码。把它抄写到受控离线介质，勾选“已保存”后才能进入工作区；不要放入聊天、截图或共享文档。
6. 进入工作区后，fresh `admin.user`固定同时拥有`identity.manage`、`access_grant.manage`和`audit.read`，原始批准者记录为该管理员自身。敏感操作要求近期MFA时，在“会话与安全”中重新输入当前密码＋TOTP；系统不会自动重放刚才的业务操作。

浏览器使用本机自签名证书时会提示证书不受公开CA信任；核对地址确实是`https://localhost:8443`后，仅在该本机安装中继续访问。不要把这个做法用于公网生产环境。
#### 1.6 从schema v13升级到v14（仅既有安装执行一次）

v14新增本地TOTP和两个独立key domain。既有v13安装不能直接执行普通`git pull && up`：旧keyring只有16个domain，新keyd会按设计拒绝启动。该升级保留业务数据，但会撤销既有本地账号会话，并要求每个active本地账号在下次密码登录时登记TOTP。

先完成并验证一次数据库备份和§3.1所述旧keyring双介质离线副本。保持当前`TEAMLEDGER_*_VOLUME`名称不变，然后严格按顺序执行：

```bash
set -eu
cd ~/team-ledger
set -a; . ./.env.docker; set +a
docker compose --env-file .env.docker down

# 此时先按§3.1完成并验证旧generation离线副本，再继续。
git pull --ff-only
docker compose --env-file .env.docker build

ack_request_id="$(cat /proc/sys/kernel/random/uuid)"
if grep -q '^TEAMLEDGER_KEY_DOMAIN_ACK_REQUEST_ID=' .env.docker; then
  sed -i "s/^TEAMLEDGER_KEY_DOMAIN_ACK_REQUEST_ID=.*/TEAMLEDGER_KEY_DOMAIN_ACK_REQUEST_ID=$ack_request_id/" .env.docker
else
  printf 'TEAMLEDGER_KEY_DOMAIN_ACK_REQUEST_ID=%s\n' "$ack_request_id" >> .env.docker
fi
unset ack_request_id

# API和keyd保持停止；把完整旧16-domain keyring原子扩展到18-domain。
docker compose --env-file .env.docker --profile key-upgrade run --rm key-upgrade

# 先安装v14数据库migration；此时仍不启动API。
docker compose --env-file .env.docker up \
  --abort-on-container-exit --exit-code-from migrate migrate

# 单独启动新keyd，再把同一18-domain generation严格确认到数据库。
docker compose --env-file .env.docker up -d --wait keyd audit-receiver
docker compose --env-file .env.docker --profile key-domain-ack run \
  --rm --no-deps key-domain-ack

# 确认成功后才开放API和其余服务。
docker compose --env-file .env.docker up -d --wait
docker compose --env-file .env.docker ps
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/ready
```

`key-upgrade`只接受完整旧16-domain或完整新18-domain inventory；重复执行完整18-domain不会再生成key。`key-domain-ack`以`.env.docker`中保存的同一request ID幂等重试，不能换ID猜测成功。任一步失败时保持API停止，保留错误输出和原数据/key volume；不要清库、重跑bootstrap、生成替代root或执行`down -v`。

成功后：

1. 用原账号密码登录，按§1.5登记TOTP并保存一次性恢复码。
2. 再按§3.1制作并验证包含18-domain新generation的双介质离线副本；旧副本继续按保留政策保存，不能冒充新副本。
3. 确认所有账号完成登记前，不要删除原数据库备份。

#### 1.7 从schema v14升级到v15（既有v14安装执行一次）

v15追加本地用户管理、fresh管理员固定安全权限和首次改密。该版本**不增加key domain**，使用既有18-domain keyring；不得重跑key、audit或identity bootstrap。升级保留业务、账号、MFA、审计和outbox数据；既有账号不会被追溯要求修改密码。bootstrap管理员的旧会话会被撤销，并补齐`identity.manage`、`access_grant.manage`、`audit.read`。

先按§5完成并验证数据库备份，按§3.1确认当前18-domain keyring双介质离线副本可用。保持全部`TEAMLEDGER_*_VOLUME`名称和`TEAMLEDGER_DEPLOYMENT_ID`不变，再执行：

```bash
set -eu
cd ~/team-ledger
docker compose --env-file .env.docker down
git pull --ff-only
docker compose --env-file .env.docker build
docker compose --env-file .env.docker up \
  --abort-on-container-exit --exit-code-from migrate migrate
docker compose --env-file .env.docker up -d --wait
docker compose --env-file .env.docker ps
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/ready
```

成功标准：migration以0退出，服务均为`Up`/`healthy`，ready返回`{"status":"ready"}`。用原账号密码登录：原有账号按原MFA状态继续，不出现首次改密；bootstrap管理员需重新登录，其会话应显示用户管理、授权和审计入口。失败时保持原volume，不执行`down -v`、不重跑bootstrap；保存错误并从已验证的v14备份恢复后再处理。

#### 1.8 从schema v15升级到v16（既有v15安装执行一次）

v16只扩展初始`admin.user`的批准委派范围：保留v15已有`audit.read`、`identity.manage`两项，补齐其余36项当前可委派的org级authority，最终为38项。该版本不增加key domain，不创建任何用户的业务grant或职责assignment，不撤销既有session，也不把`access_grant.manage`变成可委派能力。

先按§5完成并验证数据库备份，保持现有`.env.docker`、全部`TEAMLEDGER_*_VOLUME`名称、deployment ID及18-domain keyring不变：

```bash
set -eu
cd ~/team-ledger
docker compose --env-file .env.docker down
git pull --ff-only
docker compose --env-file .env.docker build
docker compose --env-file .env.docker up \
  --abort-on-container-exit --exit-code-from migrate migrate
docker compose --env-file .env.docker up -d --wait
docker compose --env-file .env.docker ps
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/ready
```

成功标准：migration以0退出，服务均为`Up`/`healthy`，ready返回`{"status":"ready"}`。原`admin.user`重新登录并完成近期MFA后，**授权** 页应显示38项“当前批准的委派范围”。这些authority只允许管理员在目标主体已具有对应`capability_assignment`时执行明确授权；不会让管理员或目标用户自动读取人员、面谈或薪资正文。失败时保留原volume和错误输出，不执行`down -v`、不重跑bootstrap；从已验证的v15备份恢复后处理。
#### 1.9 从schema v16升级到v17（既有v16安装执行一次）

v17新增Staff关联账号政策表。该版本不增加key domain、不改密码或TOTP、不撤销session，也不修改既有员工、账号、`subject_employee`、grant或审计事实。**既有账号一律不自动推断为Staff关联账号**；即使已有`subject_employee`映射也不会补默认权限。

先按§5完成并验证数据库备份，保持现有`.env.docker`、全部`TEAMLEDGER_*_VOLUME`名称、deployment ID及18-domain keyring不变：

```bash
set -eu
cd ~/team-ledger
docker compose --env-file .env.docker down
git pull --ff-only
docker compose --env-file .env.docker build
docker compose --env-file .env.docker up \
  --abort-on-container-exit --exit-code-from migrate migrate
docker compose --env-file .env.docker up -d --wait
docker compose --env-file .env.docker ps
curl --fail --cacert docker/secrets/tls-cert.pem \
  https://localhost:8443/health/ready
```

成功标准：migration以0退出，服务均为`Up`/`healthy`，ready返回`{"status":"ready"}`；原账号、员工资料和授权保持。失败时保留原volume和错误输出，不执行`down -v`、不重跑bootstrap；从已验证的v16备份恢复后处理。


#### 1.10 用户管理和一次性初始密码

完成fresh安装或升级到当前v17后，以具有近期MFA的`admin.user`打开顶部 **用户管理**：

1. 选择账号类型：
   - **非关联账号**：输入唯一登录账号、一次性初始密码和确认密码；不绑定员工，也不增加业务访问权。
   - **Staff关联账号**：除上述字段外，输入当前有效员工的精确Staff Code。该员工必须存在且尚未关联其他账号；账号、员工绑定和默认政策在同一事务提交，失败不会留下半成品账号。
2. 点击“创建用户”。成功后初始密码和Staff Code立即清空，系统不会再次显示或发送初始密码；由管理员通过受控渠道交给用户。
3. Staff关联账号默认可查看本人及当前一层administrative直属下属的员工metadata/PII和面谈metadata，并可新建面谈。范围按当前员工生命周期和直属关系实时计算；同级、上级、二层下属、已结束关系、薪资、面谈笔记/行动/评估、导出及面谈状态修改不在默认权限内。
4. 非关联账号默认没有员工绑定或任何业务权限。需要访问人员、薪资或其他模块时，必须另行按批准职责在 **授权** 中配置。
5. 新用户第一次以初始密码登录时只能修改密码；改密后必须用新密码重新登录并登记TOTP，保存恢复码后才得到business session。
6. `identity.manage`只允许账号列表/创建，`access_grant.manage`只允许在既有delegation authority内管理授权，`audit.read`只允许读脱敏审计。三项可由同一主体同时持有，但互不替代。

列表显示账号类型；Staff关联账号另显示关联的employee ID。列表不显示密码、TOTP secret、恢复码、Staff Code、员工PII或业务正文。账号停用、重置和显式权限委派仍按各自受控流程处理。

#### 1.11 日常停止、重启和更新
普通停止不会删除数据：

```bash
docker compose --env-file .env.docker down
```

以后开机或重启服务只执行：

```bash
cd ~/team-ledger
docker compose --env-file .env.docker up -d --wait
```

获取新版本：

```bash
cd ~/team-ledger
docker compose --env-file .env.docker down
git pull --ff-only
docker compose --env-file .env.docker build
docker compose --env-file .env.docker up -d --wait
```

不要重跑key、audit或identity bootstrap。普通启动会运行必要的database migration并复用既有named volumes。

#### 1.12 数据不会放在哪里、哪些命令不能用

业务数据库、keyd材料和audit材料不在容器临时层，而在三个Docker named volumes。`down`、重建image和电脑重启不会删除它们。查看实际名称：

```bash
docker volume inspect "$TEAMLEDGER_DATA_VOLUME"
docker volume inspect "$TEAMLEDGER_KEY_VOLUME"
docker volume inspect "$TEAMLEDGER_AUDIT_VOLUME"
```

**有任何需要保留的数据时，禁止执行：**

```text
docker compose down -v
docker volume prune
docker system prune --volumes
```

Named volume不是备份。正式使用前必须按§5建立业务数据库加密备份，并按§3.1把root/keyring保存到两个不同离线介质；数据库备份、key材料和audit材料必须分开保管。

#### 1.13 常见问题

长期服务或migration失败时运行：

```bash
docker compose --env-file .env.docker ps -a
docker compose --env-file .env.docker logs --tail=200 \
  data-init key-check migrate keyd audit-receiver audit-forwarder api
```

`key-bootstrap`、`audit-bootstrap`和`identity-bootstrap`使用`run --rm`，container退出后不会保留；它们的错误只显示在执行该命令的当前Terminal。失败时不要关闭Terminal，先保存不含密码/密钥的错误文本，修正后只重跑该条失败命令。

| 现象 | 检查和处理 |
|---|---|
| `docker: command not found` | Docker未安装或Windows Docker Desktop未启动。回到§1.1，直到`hello-world`成功。 |
| `docker compose`不可用 | 安装Compose v2 plugin；不要改用旧`docker-compose`。 |
| Windows出现owner、mode、`unsafe ... ancestry`错误 | 在Ubuntu WSL中执行`pwd`；路径必须在`/home/...`，不能是`/mnt/c/...`。重新clone到`~`，不要关闭安全检查。 |
| `permission denied`访问Docker socket | Linux按Docker官方post-install配置当前用户，重新登录；或仅给Docker命令加`sudo`。 |
| `address already in use` / 8443被占用 | 编辑`.env.docker`，同时修改`TEAMLEDGER_DOCKER_PORT`和`TEAMLEDGER_PUBLIC_ORIGIN`，例如改为`9443`和`https://localhost:9443`；然后关闭当前Terminal，打开新的Linux/Ubuntu Terminal，回到仓库再启动并访问新端口。新Terminal避免先前导出的环境变量覆盖`.env.docker`。 |
| container为`unhealthy`或`Exited` | 用上面的`ps -a`和长期服务`logs`找第一个失败服务；不要只反复重启API。若失败的是bootstrap one-shot，使用当前Terminal中的直接输出，修正后只重跑该条失败命令。 |
| 重跑bootstrap时报“已存在”或`key control failed` | 先回看第一次执行结果：只有明确看到`key directory initialized`或对应bootstrap成功退出才可视为已完成并继续下一步。首次失败不得猜测成功、删除volume或覆盖key；保存错误并按上段只重试失败命令。 |
| 忘记初始密码 | 不要重做安装；使用后文maintenance profile的`local-account-reset`受控重置账号。 |
| curl报告证书错误 | 必须保留`--cacert docker/secrets/tls-cert.pem`，URL必须是证书覆盖的`localhost`或`127.0.0.1`。 |
| TOTP设备遗失，但恢复码仍在 | 在登录页选择“使用恢复码”，输入username、当前密码和一次性恢复码，只进入受限恢复页；设置新验证器并保存新的恢复码。恢复码不能直接进入业务页面。 |
| TOTP设备和恢复码都遗失 | 不能从网页关闭MFA或绕过第二因素；由有权维护者按下述“离线MFA重置”操作。 |
| 审计页或用户管理提示缺少权限 | fresh/bootstrap `admin.user`从v15起固定拥有`audit.read`、`access_grant.manage`和`identity.manage` direct grant；先确认已升级到当前v17、已重新登录且近期MFA有效。v16另给该管理员38项当前可委派authority，但不自动创建目标用户的职责assignment或业务grant。v17 Staff关联账号只取得本人/当前一层直属下属的窄默认读取与面谈创建资格；非关联账号仍默认零业务/安全权限。其他访问须按批准职责显式配置对应assignment＋grant，不能靠TOTP、账号名称或直接改库获得。 |
| 最新人员模板上传后仍提示无法解析 | 展开 **批量上传人员** 查看具体`Employees!单元格`、字段和原因。日期单元格必须是文本，可填写`YYYY-MM-DD`、`YYYY/M/D`、`M/D/YYYY`、`YYYY.M.D`或`YYYY年M月D日`；年在后固定按月/日/年解析。公式和Excel数值日期必须转为纯文本。结构错误或服务端故障会显示请求ID；管理员可在API日志中按`PERSONNEL_IMPORT_REJECTED`（工作簿结构）或`PERSONNEL_IMPORT_ROW_REJECTED`（逐行字段）及`request_id=...`定位，日志不记录单元格内容。 |

只有在**确认是全新测试安装且所有数据都可以永久删除**时，才能彻底重置：

```bash
docker compose --env-file .env.docker down -v
sudo rm -rf docker/secrets docker/maintenance docker/audit-maintenance backups
rm -f .env.docker
```

然后从§1.3重新开始。该操作不可恢复，不适用于任何重要环境。

离线MFA重置保留MFA强制要求，只删除旧因子并把账号恢复为`enrollment_required`。准备bootstrap时保存的`org_id`、`subject_id`，把示例username替换为目标账号；canonical JSON不能有末尾换行：

```bash
set -eu
set -a; . ./.env.docker; set +a
printf '%s' '{"username":"admin.user"}' \
  > docker/maintenance/local-mfa-reset.json
sudo chown "$TEAMLEDGER_MAINTENANCE_UID:$TEAMLEDGER_GID" \
  docker/maintenance/local-mfa-reset.json
sudo chmod 0600 docker/maintenance/local-mfa-reset.json
reset_request_id="$(cat /proc/sys/kernel/random/uuid)"
docker compose --env-file .env.docker --profile maintenance run \
  --rm --no-deps maintenance \
  /app/teamledger-identity local-mfa-reset \
  -backend sqlite \
  -dsn-file /run/teamledger-maintenance/sqlite-dsn \
  -keyd-socket /run/teamledger-keyd/keyd.sock \
  -input-file /run/teamledger-maintenance/local-mfa-reset.json \
  -org-id '替换为org_id' \
  -subject-id '替换为subject_id' \
  -request-id "$reset_request_id"
sudo rm -f docker/maintenance/local-mfa-reset.json
unset reset_request_id
```

只有命令成功后才删除输入文件。网络或终端结果不确定时，用**相同**request ID和相同文件重试；不得换ID。成功会撤销该账号全部会话、旧TOTP、恢复码和pending登记并写审计。用户随后以现有密码登录，只能重新登记TOTP，不能以密码单独进入工作区。

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

Compose默认SQLite，不承诺数据库角色隔离。PostgreSQL部署由当前v14 schema owner执行`docker/postgres/audit_roles.sql`，再由部署系统为四个NOLOGIN角色配置本地LOGIN凭据/成员关系和强制TLS；runtime不得使用schema owner。receiver只获`schema_version`和receiver chain/ledger所需权限，forwarder获`audit_event/audit_outbox`读取、outbox更新及receiver status heartbeat写入，离线maintainer只获ledger/outbox SELECT，API login只继承`teamledger_audit_api`。角色本身不创建LOGIN、不分发凭据、不完成生产身份认证。

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
