# TeamLedger 开发规则：TDD、双数据库与交付门禁

- 日期与来源查阅日期：2026-10-15。
- 状态：当前开发与交付规则；基础 CI 见第 10.1 节，规则本身不代表某项功能已发布或通过生产启用验收。
- 适用：独立开发者和 AI assistant；Go 模块化单体 API、Vue3/TypeScript/Vite、每次部署选择 SQLite 或 PostgreSQL 一个后端，不双写。
- 用户约定：实际开发采用TDD；每个整体交付task完成验证与审查后必须commit并push，不补造历史提交。自2026-10-15既有环境通知起，未来持久化变更必须提供已部署版本到新版本的安全migration，不得再以空库重建替代。
- 关联：[整体功能规范](FUNCTIONAL_SPEC.md)、[整体技术规范](TECHNICAL_SPEC.md)及仓库README。

## 1. 结论、归属与适用限制

### 1.1 TDD 可行，但不能代替业务决定或系统验收

Go 的 `testing`、table-driven tests、subtests、race detector 和 fuzzing，以及 Vue3 的 Vitest＋Vue Test Utils，足以支持小步测试驱动开发。确定性的金额、有效期、授权、加密上下文、业务状态转换适合先写行为测试；数据库约束、并发、迁移和浏览器全链路需要真实集成测试，不能仅靠单元测试。

本项目采用的 TDD 定义是：先列下一组行为案例，再反复执行 RED → GREEN → REFACTOR。[Fowler 的说明](https://martinfowler.com/bliki/TestDrivenDevelopment.html)支持这一流程。**Go 官方教程说明的是工具能力，不是“Go 官方要求先写测试”**；其 Add a test 教程本身从已有代码开始添加测试。[Vue 官方指南](https://vuejs.org/guide/scaling-up/testing.html)建议早测试、分层测试和测试用户行为，并不证明 TeamLedger 的功能已经正确。

测试无法替用户确定员工自助范围、历史面谈交接、审批分权、币种/税制、AI 外传许可或容量目标。未确认策略不得以写了测试为由成为既定需求。法规适用、渗透测试、密钥设施安全、人工模型评估和容量验收也不能由 TDD 成功替代。

### 1.2 代码与文档同仓归属

| 资产 | 唯一归属 | 规则 |
| --- | --- | --- |
| Go/Vue代码、永久测试、SQL迁移、构建/CI、合成fixture及fuzz语料 | `team-ledger` | 与当前功能、技术文档同仓维护 |
| 当前PLAN、功能/技术说明、开发规则、ADR及公开验证摘要 | `team-ledger` | 与源码同仓维护；历史私有会话和本机路径不迁入public文档 |

功能规范、技术规范和开发规则只在本仓库维护。代码注释和可执行契约不得形成冲突的第二套说明；可长期捕获回归的行为应进入永久测试。

## 2. 每个开发 task 的 Definition of Ready

一个 task 是端到端可交付的行为切片，不是一次 RED、一次测试、一个分工或一次 review。执行前必须满足：

1. **登记和 PLAN**：实质开发先写`docs/plans/<TASK-ID>.md`，记录唯一Task ID、范围/非目标、交付、验证命令/环境和审查安排。小问题可以简化PLAN，但不能借拆task豁免安全或架构变更。
2. **需求可判定**：关联 F-ORG-001、F-INT-001、F-COMP-001、F-BONUS-001、F-AI-001、F-SEC-001、F-DB-001 中的实际受影响 ID；说明调用者、输入、前置状态、可见结果、拒绝条件和写入副作用。列正常、边界、错误、不变量、transition 案例，而不是“做完模块”。
3. **策略状态清楚**：区分用户约定、已接受设计、研究建议和待确认。对拟启用的业务策略先获得确认并同步功能规范；不能用测试私自选择政策。受阻策略切片暂不进入实现；不受影响的确定性切片可继续，但原 task 不能悄悄缩小验收。
4. **安全边界明确**：定义 role capability＋org/team/employee scope＋数据类别＋对象 grant/当前关系＋purpose/MFA 条件；定义哪些对象可读/写/审批/导出、先授权后解密、AI 可用输入与禁止输入。fixture 全是合成数据，无员工资料、生产凭据或真实密钥。
5. **存储与接口明确**：列 API JSON 契约、金额字符串/币种/scale、有效期边界、revision、数据库事务和约束、两种方言迁移的影响；外部身份、KMS、LLM 边界与失败状态可定义。未接入外部设施就不能把其生产验收列为已满足。
6. **可运行条件明确**：代码路径和工具链已接入；真实 SQLite、真实 PostgreSQL、浏览器与所需受控外部集成环境可用，或准确列为阻塞。PLAN 记录支持版本、锁定依赖、如何创建/清理隔离测试数据、预期测试清单和通过标准，不能只写“CI green”。

变更目标、策略、数据库支持范围或验收前，先更新 PLAN 和相应功能/技术说明；这不是让测试迎合实现的许可。

## 3. 每个行为案例的 RED → GREEN → REFACTOR

### 3.1 先列案例，再选最小有效 RED

- 测试必须调用真实被测行为，准备合成前置状态，执行操作，断言调用者可观察的输出/副作用。命名说明功能 ID 和行为，不以实现类名/方法名清单代替意图。
- 建立正常案例和关键负向案例的测试清单，优先选择会暴露核心边界的案例；每轮选一个小切片，不先实现整模块再补一批“先写过”的测试。
- **有效 RED 是预期行为断言实际失败**：例如错 employee 的 AAD 被接受、越权读取返回正文、未生效调薪改变现状、旧 revision 覆盖成功、提交界面错误地显示已保存。
- 缺依赖、连接不到数据库、TypeScript/Go 编译失败、导入/选择器配置错误、测试未被发现、空套件和意外超时是环境或测试问题，**不能冒充行为 RED**。新接口尚不存在时，可补最小可编译入口让测试执行；它不是完成实现，最终不能留 stub/no-op。
- 记录同一案例的命令、代码 revision/工作区状态、预期断言和实际失败摘要；不需要留敏感完整日志。失败原因不符合行为预期，先修环境/测试，再获得真正 RED。

### 3.2 GREEN 是最小真实实现

- 实现能满足这一行为的最小生产逻辑，正确处理授权、金额、事务和错误；不能仅对 fixture ID 特判、返回固定答案、吞错、禁用校验、用 mock echo 让测试通过。
- 当前案例转绿后，运行受影响既有行为测试，确认没有牺牲另一个状态/边界；涉及持久化的切片在两种真实后端执行契约再进入该切片集成完成状态。
- 外部 I/O 可有可控 fake，但业务判断、加解密、状态流转、数据库持久化不能由 fake 替代其集成证明；“最小”不是省掉安全边界。

### 3.3 REFACTOR 只在绿灯下进行

- 在行为测试为绿时整理命名、重复、职责和错误处理；每次重构后保持相关测试为绿。重构不同时改变业务政策或 API 行为。
- 无需改进时可明确记录“本轮无需重构”；**不为流程硬造接口、通用框架、工厂或抽象**，也不虚构做过重构。默认保留模块化单体与必要的两个数据库适配，不增加 ORM、微服务或队列预设。
- 若测试因私有方法或源代码布局改变而坏，先辨别是否为不允许的实现绑定；不得机械修改预期使真正的业务回归变绿。
- bug 修复保留永久回归测试：同一测试在修复前实际失败，在修复后实际通过。无法安全取得旧运行环境时记录证据限制，不伪称已重现；仍须验证当前错误边界和修复行为。

## 4. 永久测试准入规则

永久 tests 只保护**真实行为、边界、错误、不变量和状态转换**。测试的维护成本必须对应可说清的风险；不设置“每个函数必须一个 test”或数字覆盖率目标。

### 4.1 应保留

- 消费者可见 API、领域契约、用户操作后 UI 状态、实际写入/拒绝写入、历史 as-of 查询、授权拒绝、加密完整性、版本冲突与事务原子性。
- 精确金额、币种、有效日、公开机器可读错误码、规范规定的数据字段/格式等实际契约断言；这是业务数据，不是措辞 pin。
- 使用真实数据库验证复合外键、唯一性、跨组织隔离、迁移、回滚和并发；通过公开接口或持久化安全边界观察结果。
- 每个业务状态有允许转换和拒绝转换；拒绝后确认没有批准记录、付款记录、AI 发布结果等不应存在的副作用。
- 收缩后的 fuzz 反例、线上 bug 的合成回归案例；有业务解释的边界语料。

### 4.2 禁止以这些测试凑交付

- 读取 Go/Vue/SQL/文档**源文本**并检查是否出现函数名、权限词、关键字、文件布局、SQL 字面拼接；SQL 必须实际执行，不能靠文本含有 `FOREIGN KEY` 证明约束存在。
- 断言私有变量、组件内部方法、算法步骤、无契约意义的调用次数/调用顺序、具体库实现、仅转发 wiring；要测连接是否真的完成消费者行为，不是“调用了某个方法”。
- 固定自然语言提示/注释/日志/AI 草稿措辞，或因重构/文案改动机械重 pin 大段 snapshot；全页 HTML/snapshot 不能替代正确性。这里不要求建立永久措辞/snapshot 测试；视觉/交互风险用有意图的 UI/浏览器观察处理。
- mock 自己的权限、加密或核心业务再断言 mock 返回值；空 test、全部 skip、无限重跑直到绿、隐藏失败、为覆盖率调用无意义分支。
- 把行/分支覆盖率、test 数量或 snapshot 数量当正确性与完成标准。覆盖报告可辅助发现遗漏路径，不能成为数字 KPI；验收依据是需求与风险案例。

## 5. 分层工具与日常运行方式

以下规则适用于当前仓库。实际包路径、锁定依赖、测试入口和Docker命令以源码、`go.mod`、`web/package.json`及README为准；task PLAN记录本次实际选择和结果，不得把示例命令冒充已运行证据。

### 5.1 Go：testing、table、subtests、race、fuzz

- 用标准 `testing` 和 `_test.go`，Arrange → Act → Assert；相关案例用 table-driven tests＋`t.Run` 命名子测试，便于按行为定位和选择执行。[官方 subtests 资料](https://go.dev/blog/subtests)说明这一工具能力。
- 单元层覆盖金额解析/精度/溢出、日期窗口、确定性状态规则、授权决策、AEAD 的成功与失败契约。API 层调用真实 handler/service，不能 mock service 后只测 JSON 转发。
- 快速循环可用 `go test -count=1 -run '具体行为' <实际包>`；集成用完整受影响套件及 `go test -count=1 ./...`，依照实际工程的集成入口同时运行真实数据库。明确 `-run` 确实选中了案例，不能把“没有运行任何 test”算 GREEN。
- fixture、clock 和随机输入隔离；需要“某日生效/lease 超时”时使用可控时钟而非长 sleep。使用资源清理机制关闭连接/服务、回滚或删除专用测试库；共享状态不能未经隔离就 `t.Parallel`。
- 集成门禁运行 `go test -race ./...` 并覆盖实际并发路径。race detector 只检测执行路径上的 Go 内存数据竞争，不证明数据库没有 lost update、写偏差或时间窗口循环。支持平台/工具链条件必须写明；不支持的运行环境需安排受支持 runner，不能默默去掉 race 门禁。
- fuzz 针对金额/API 输入、规范 AAD 编码、畸形密文/metadata、有效期边界等定义可判定属性：不 panic、不越界、不接受无效上下文、合法往返不损值。**仅“Seal/Open 往返成功”不足以证明绑定安全**，还需独立错误上下文与篡改拒绝案例。
- 普通 `go test` 执行 seed/已保存回归语料；主动 fuzz 在指定实际包中使用 `go test -fuzz='具体目标' -fuzztime=30s <实际包>` 这类有界运行，每个适用目标分别执行。30s 是可调整的初始运行预算建议，不是正确性或覆盖率阈值；高风险变更/发布另安排更长运行并记录实际时间与种子/反例。发现反例最小化后留在代码仓库，不留真实人事信息。

### 5.2 Vue3：Vitest＋Vue Test Utils

- Vitest 用于 TypeScript 纯逻辑/composable 和组件行为；Vue Test Utils `mount` 真实组件，用输入、点击、提交与 DOM 可见结果/asserted 公共事件验证，不访问 `wrapper.vm` 私有状态驱动测试。
- 必须正确等待 Vue 更新与异步请求；`await setValue/trigger`、等待受控 promise/更新，不能用随机 sleep 掩盖异步错误。VTU 的示例说明了异步 DOM 更新和用户操作测试。
- 覆盖 loading → success/error、取消/重新加载、空/边界输入、API 拒绝、保存冲突、权限失效后敏感界面清空及 stale response 不重新显示已撤权数据。按钮隐藏不能证明服务端授权；服务端负向请求另测。
- 金额从 API 到表单/展示往返保留整数十进制字符串，覆盖超过 JS 安全整数范围的值；不得经过 `Number`/float 造成取整。日期展示和 as-of 请求按约定的业务日期/时区测试，而非依赖开发机本地时间。
- 网络边界可用可控响应模拟超时、拒绝、乱序响应；不要把所有子组件 stub 掉后宣称页面可用。组件测试负责界面契约，真实 API/数据库安全由集成/E2E 证明。
- 开发可 watch，门禁必须使用单次退出的 `vitest run`（通过实际已锁定的包管理器运行）。禁止 `passWithNoTests` 使空套件通过；类型检查、构建和静态检查是另外的门禁，不算行为测试。

### 5.3 少量真实端到端与 smoke

- 采用一个浏览器 E2E runner（如 Playwright，具体选型在接入时固定），测试真实生产构建的 Vue、真实 Go API、真实被选数据库和合成身份/数据。不拦截核心业务 API 回包，不把 Vite dev server/组件挂载冒充正式全链路。
- 首批保留高价值短路径：授权用户保存并重载分区面谈；无权用户直达对象 URL/API 仍被拒；薪酬批准/有效日与历史读取；旧 revision 冲突不会覆盖；经理交接撤权后重载/旧页面不再泄露；AI 草稿未人审不可发布、失效来源不可继续展示。
- 支持双后端期间，同一关键浏览器/API 路径分别以 SQLite 和 PostgreSQL 部署配置执行，不需要为每个单元边界复制一套长 E2E。
- 每个 task 集成阶段必须**启动实际构建产物**，检查启动、配置、数据库迁移、真实 API 写读/拒绝、页面加载与受影响用户操作；检查合成敏感 marker 未出现在响应错误、日志或不应持有它的存储边界。健康检查返回 200 或编译成功不等于 smoke 完成。
- 有界等待使用可观察条件；失败保留脱敏证据并处理根因，不靠追加重试消除失败。截图、trace 和网络日志只含合成信息；记录构建 revision、数据库/浏览器版本、场景和结果。纯后端 task 仍验证真实程序路径；无 UI 改动可复用已有关键页面 smoke，并说明受影响范围，不能声称新增界面已验收。

## 6. 双数据库共同契约与额外验收

### 6.1 一份行为契约，两次真实执行

1. 在 `team-ledger` 维护同一共享业务契约/fixture/断言，分别注入 SQLite 和 PostgreSQL 的真实持久化适配。基线接口是 `database/sql`＋`modernc.org/sqlite` / `pgx v5 stdlib`；不为测试另立通用 ORM。
2. SQLite 运行隔离的**真实文件数据库**，涉及 WAL、重启和并发时按实际模式/多连接运行；仅内存 SQLite 不足以验收文件/锁行为。PostgreSQL 使用真实实例/隔离库及角色，锁定测试版本，不能由 SQLite、SQL mock 或兼容语法解析器替代。
3. 两次必须有明确后端标签、版本、测试清单和各自结果；接口相同不意味着 SQL/锁/迁移相同。共享契约不能按后端分支降低金额、授权、有效期或原子性预期。
4. 缺数据库、错误 DSN、服务未起、migration 失败是**失败/阻塞**，不能 `t.Skip`、跳过 job 或 fallback 到另一库后给双库绿色。开发时单选一个后端只算快速局部反馈；交付要求另一后端也真实执行。测试不能触碰生产库。
5. 基线两库都验收：复合外键与 org 所有权、唯一性/历史约束、真实参数绑定、rollback 无半写、revision CAS 拒旧版本、as-of 结果、已批准记录不可覆盖、敏感字段持久化密文及授权读取。加密/权限的契约通过真实业务路径完成，不仅 roundtrip driver fixture。

### 6.2 方言与迁移必须另外测试

- 两后端各有对应DDL/migration；参数占位符、BLOB/BYTEA、布尔/整数/时间、JSON、索引/约束、affected rows、事务/锁和错误分类明确映射。不能把SQLite动态类型容忍误当PostgreSQL验证，不能宣称“换DSN即兼容”。
- 任何影响schema、持久化格式、密文AAD、索引key版本或不可变事实解释的task，设计前必须以只读preflight登记既有环境的应用commit、`schema_version`和checksum，列出支持的source→target matrix；无法取得实际source时保持阻塞，不能猜测它等于仓库HEAD。
- 每次schema变更，两库都实际测试空库安装、从每个支持的既有版本带合成数据升级、迁移中断/重启/重复运行和切换后的真实程序；检查金额/历史/密文/key metadata/receipt/grant/audit引用保真及约束实际生效。SQLite按连接落实外键等配置；PostgreSQL按真实运行角色验证权限，不能只以超级用户执行。
- 已部署migration和已经冻结为兼容源的baseline bytes/checksum不得重写；新增版本和前向migration升级。先验证备份恢复，再受控停写/迁移；失败必须安全停留在旧版本或已验证恢复目标，不得自动清空、fallback空库或用重新导入冒充原子升级。若不支持down migration，明确采用已验证备份恢复/前向修复，不虚构自动回退。
- 涉及后端切换时，另验收受控停写、导出/导入、数量与关键不变量/金额/密文校验、切换后的真实程序smoke、回退条件；库间数据迁移不是DDL migration，不能借共享契约宣称已完成。

### 6.3 并发不能由 race detector 代替

- 用至少两个真实连接/事务，通过 barrier 明确制造竞争和交错，不能用单连接顺序操作或随机 sleep “证明并发”。断言最终业务状态及每个请求的成功/冲突/拒绝结果，原始数据库错误字符串不是跨库业务契约。
- 组织/汇报线变更先在事务取得组织 guard 写锁，再检查受影响窗口全部边界点；工资变更取得 employee guard。验证两个单独看来合法的并发变更不能合成循环、重叠行政经理或丢失更新；不能采用无锁 SELECT 后写入。
- SQLite 额外验收实际 writer 竞争、`SQLITE_BUSY`/超时/取消和 WAL 下读写边界；PostgreSQL 额外验收行锁等待、死锁/序列化失败及事务失败后整笔回滚。只在设计已规定重试时测试有界整事务重试及幂等，不额外引入无限重试策略。
- revision 冲突拒绝后无覆盖；重复批准/付款/定时窗口执行不能生成重复事实；lease 失效的旧 worker 不能覆盖新结果。AI 外部调用不持有数据库写事务，SQLite 仍由主 Go 服务独占数据库访问，worker 通过受限内部 API 工作。
- 此处验收不证明人数/吞吐容量；负载目标、生产存储和超时预算需用户/部署需求确定后另测。

## 7. 高价值 acceptance 矩阵

每个实际 task 从下表选择全部受影响项，在 PLAN 记录具体输入/前置状态/预期结果/测试层和证据；该表不是已通过报告。涉及持久化的集成项默认在两种真实数据库执行。策略依赖项在被接受前不启用，不能删掉安全负向项或以 UI test 代替 API test。

| 功能 ID / 风险 | 正向、边界与状态 | 消费者可见负向/不变量 | 最低验证层 |
| --- | --- | --- | --- |
| F-ORG-001 团队、人员、任职/汇报历史 | 分离 team 树、employee、成员/任职、行政/虚线关系；按 as-of 取历史；覆盖起止边界、相邻区间、未来/回溯变更 | 跨 org、自环、每时点多行政直属经理、仅中间窗口存在的循环拒绝；虚线不获薪酬权限；并发改线不能绕过约束 | Go table/subtests；API＋双库历史/并发 |
| F-INT-001 分区笔记与交接 | shared/manager_private/hr_confidential 独立读取；版本/参与者事实/共享行动项；改稿、完成、重载、旧 revision 冲突 | 历史 author/participant/manager 身份不永久放行；换经理撤旧管理 grant、新经理不自动继承全历史；无权用户详情/列表/搜索/导出不露正文 | Go 授权；API＋双库；Vue 状态；交接 E2E |
| F-COMP-001 条款、批准调薪与有效期 | before/after/原因/有效日及工资周期、税前税后显式；批准前后、有效日前后 as-of；supersedes/reversal 纠错可追溯 | 普通经理/IT/DB 管理员/AI 不默认读薪酬；未批准/未来记录不改变当前薪资；已批准内容不能覆盖；越权提出/批准/导出独立拒绝 | Go 状态/金额；API＋双库事务/CAS；关键 UI/E2E |
| F-BONUS-001 目标、award 与 payment | 奖金目标、批准 award、实际 payment/paid status 分开；敏感扩展 schema/version、size/allowlist | “批准”不等于“已支付”；重复支付不生成第二事实；扩展 JSON 不能旁路薪酬权限/金额规范；无效扩展拒绝后不半写 | Go 状态/输入；API＋双库；Vue 往返 |
| F-COMP-001/F-BONUS-001 金额 | int64 最小单位＋currency/scale；API 整数十进制字符串；费率/比例为受限 exact decimal；零值、范围边缘、JS 大整数往返 | 超 int64/精度/scale、无币种、币种混算拒绝；不得 float 隐式取整；是否允许负值/舍入规则需对应政策确认 | Go table＋fuzz；Vue；API＋双库 |
| F-SEC-001 授权与先授权后解密 | capability/scope/category/grant/current relation/purpose/MFA 分别覆盖；授权者读写，拒绝事件可审计 | 未登录/缺 scope/跨 employee 或 org/缺目的或 MFA/撤权拒绝且无明文；在受控 KMS 不可用时，无权请求仍按授权拒绝而非触发解密错误，且外部服务无该请求；列表与批量不绕检查 | Go 决策；真实 service/API＋双库；受控外部 I/O 观察 |
| F-SEC-001 AEAD、密钥与存储 | 写库前 AES-256-GCM；版本新 DEK、独立用途 KEK；合法授权回读；KEK rewrap 后读取、历史版本处理 | 错 org/employee/record/purpose/schema 的规范 AAD、tag/密文/wrapped DEK 篡改、未知 key/格式/不可用密钥拒绝；不降级明文；DB/WAL/备份与日志无合成正文/薪资 marker | 真实 Go crypto；API＋双库文件/存储边界；KMS 集成 |
| F-SEC-001 恢复与审计完整性 | 库备份＋独立 key 恢复，重启后授权读取；审计只含必要 actor/object/action/时间/结果 | SQLite 备份不遗漏 WAL；仅有库无 key 不可解密；旧密文重放不能被误当最新批准事实；恢复后版本/历史一致；审计无薪资/正文 | 真备份/恢复演练＋API；外部审计边界验收 |
| F-DB-001 原子性、迁移、版本 | 两库同契约；空库/升级；事务与 CAS；约束从真实写入观察 | 外键/跨 org 失败、迁移失败、取消/断连、锁竞争后无半写/丢更新；缺后端不得 skip 成功 | 双库真实迁移与多连接集成 |
| F-AI-001 输入、目的与发布 | 确定规则先产完整度/逾期/行动项状态；只交付已批准最小片段；草稿含来源版本/引用、人审发布；pending/running/draft/reviewed/published/failed/expired 等实际状态按规范映射 | 拒 salary/private/HR 域和 shared 中夹带的工资/健康敏感文本外传；无外传许可不能调用 provider；无引用/伪引用/格式错不得发布；不评分排名或自动薪酬雇佣决策 | 真实最小化/权限 service；可控 provider I/O；API＋双库；Vue 状态 |
| F-AI-001 派生 ACL 与定时任务 | ACL 不宽于输入读者交集；持久化窗口/输入版本/lease；失败可见、人审可拒 | 来源改版/撤权使旧结果失效；结果不可借 AI 扩权；重复窗口不重复发布；过期 worker 不能写新结果；provider 失败不标“已评估成功”；模型无 DB/HTTP/密钥工具凭据 | Go 状态；API＋双库并发；UI；发布 E2E |

有效期区间表示、业务日期/时区、缺经理是否合法、奖金分期/撤销与审批分权等具体政策须在功能/技术基线明确后编写精确案例。保守安全默认和研究模型不是用户已认可所有业务参数；未决状态必须留在 PLAN/规范，而非用测试将其冻结。

敏感 marker 检查是对**运行产生的数据库/日志/网络/备份**进行泄露观察，不是源文本测试；未发现某个 marker 只证明该合成场景未在所检查位置出现，不能称“全库无泄漏”或端到端加密。必要 org/关联/有效期 metadata 仍可暴露关系；宿主/应用进程被攻破可能暴露明文。AEAD 自身不防旧密文重放，需真实版本/历史/审计完整性校验；DBA 防篡改要求独立权限保管的外部审计，不能由同库审计 test 证明。

## 8. AI 的确定性 CI 边界与另行模型评估

1. 普通 CI 不调用随机真实 LLM 后逐字比较输出，也不固定模型自然语言措辞或 snapshot。temperature=0 等配置不能被当作严格确定性保证。
2. provider 适配器可用可控 fake/本地 HTTP 服务模拟**外部 I/O**：成功结构、超时、拒绝、限流、格式错误、伪引用、敏感请求、取消。可固定模型响应以驱动真实业务解析和状态转换，不得让 fake 实现权限、最小化、加密、数据库或审批规则。
3. 确定性测试检查送到 provider 边界的真实输入、目的/许可、敏感过滤结果、引用校验、版本/ACL、拒绝发布及错误/过期状态；使用合成敏感数据验证剔除或阻断。回显 fake 只能说明 I/O/解析边界通了，不能证明权限、加密、核心业务或模型理解正确。识别敏感自由文本并非无漏检承诺；无法可靠最小化的内容不外传，不能以删字段名代替内容审查。
4. provider真实适配另跑受控集成，检查实际协议、身份、超时和数据处理限制；部署选择OIDC时也必须验真实IdP，keyd、local identity和audit receiver则验本部署的真实独立进程及故障边界。fake不替代目标部署配置的生产证明。
5. 模型质量评估单独登记实际模型/provider/version、prompt/version、参数、合成案例、可复现输入与人工 rubric。覆盖引用正确、遗漏/幻觉、支持需求草稿、prompt injection、敏感外泄、禁止评分和拒绝发布；人审记录结论，不把来源文本当指令或给模型工具凭据。
6. AI生产启用前，用户确认provider、法域/数据出境与处理许可、保留策略、人工发布权限及评估接受标准，再实际执行评估和发布门禁；失败不得绕过。当前仓库未记录真实provider模型质量评估或生产启用批准，因此不能把确定性测试解释成此类证明。

## 9. 推荐模块与迭代顺序

每次迭代是有API、必要界面、持久化、权限、文档和验收的窄纵向切片，不先堆完所有底层、也不最后才加安全。下表记录采用过的依赖顺序并继续约束后续变更；当前实现状态以[功能规范](FUNCTIONAL_SPEC.md#11-稳定功能与当前状态)为准，新task仍须先登记ID/PLAN。

| 顺序 | 交付切片与依赖 | 必须先证明的价值 |
| --- | --- | --- |
| 1 | F-SEC-001＋F-DB-001 最小安全纵切：合成受保护对象、身份/权限、真实 AEAD、两适配/迁移、API 与最小界面读取 | 授权用户可持久化/重载，无权和错 AAD 拒绝；两库契约从第一条路径开始运行，不先存明文 |
| 2 | F-ORG-001：团队/人员/职位、任职归属与行政/虚线历史；复用权限、密钥和 guard 事务 | as-of 与中间窗口约束真实成立，多连接并发不会生成循环/重叠 |
| 3 | F-INT-001：版本/分区笔记、参与者、行动项及经理交接 | 历史可追溯而权限不永久继承，交接/撤权后的 API 与页面不泄漏 |
| 4 | F-COMP-001：Money、工资周期/税前税后、条款、批准调薪、生效与纠错；依赖确认的审批/币种政策 | 钱值往返不损失，未来批准不提前生效，授权/不可覆盖/冲突均成立 |
| 5 | F-BONUS-001：目标、award/payment、敏感扩展；复用已验证 Money/薪酬权限 | 批准与支付不混同，重复/撤销路径及扩展边界可审计 |
| 6 | F-AI-001：先确定状态与持久 job，再最小化 provider 草稿/引用/交集 ACL、人审与失效 | 不接 LLM 也能准确显示确定状态；接入后不扩大权限、不自动决定、不将失败标成功 |
| 7 | 生产启用前收敛 F-SEC-001/F-DB-001 运行保障：真实keyd与选定identity mode、密钥轮换、备份恢复、迁移/部署smoke、必要负载和AI独立评估 | 代码测试绿之外，部署和恢复可实际执行；仅有条件满足的能力允许启用 |

密钥管理、备份设计和真实外部集成应在相关模块开发中逐步落实，第 7 步是启用验收，不是允许此前绕过安全。与人数、部署、现有身份系统和法域相关的未决事项只阻塞对应启用/策略切片；不能让 AI assistant 自选答案或声称整个产品已验收。

## 10. 从每步测试到集成的完整门禁

下表是整体交付门禁；第 10.1 节的基础 CI 自动执行其中的静态检查、双库测试和 Web 构建入口，其余门禁仍需按实际 task 执行。技术规范、task PLAN和公开验证摘要记录实际环境、范围、命令和结果。

| 阶段 | 必须执行/提供 | 不通过时 |
| --- | --- | --- |
| Ready | 第2节条件；已确认的验收案例与同仓代码/文档范围；测试清单 | 未决业务先确认；环境/引用未接入记录准确阻塞，不伪造 |
| 每个 RED | 最小真实行为测试实际失败、预期与实际原因一致 | 编译/依赖/DB 错先解决，不能算 RED |
| 每个 GREEN/REFACTOR | 同一案例转绿＋受影响既有 tests；重构保持绿，必要时双库局部契约 | 修根因，不删安全断言、不重 pin；不得推进该行为为已完成 |
| 模块/切片集成 | 受影响 Go/Vue 全行为套件、真实 API、两库共享契约及额外并发/迁移、适用 fuzz seeds/有界 fuzz、race | 任一库/套件缺失或失败即未完成；独立分工不并发验证半成品 |
| 整体 task 集成 | 集成负责人对最终候选 revision 统一运行完整 Go tests/race、Vitest 单次运行、构建/类型/静态检查、双库迁移与契约、关键浏览器 E2E、真实程序/界面 smoke；适用外部集成/恢复 | 如实记录运行和未测；缺必要环境阻塞，不以 reviewer 代替运行 |
| 文档和证据 | 全量最新功能/技术说明、迭代/决策、测试/迁移追溯及同仓Task/commit/PR链接；合成且脱敏的实际结果 | 文档仍写旧行为或声称假成功，不进入交付完成 |
| 两轮 review | 整体执行完成后第一轮 luna → 修正/必要重验 → 第二轮 luna 检查完整交付和第一轮闭环 | 不并行、不能以两个同批意见冒充串行；阻塞问题修正后补复核 |
| Done | 第 11 节全部满足，PLAN、文档索引、review及公开验证摘要更新到真实状态 | 不能仅因 PR 合并/CI 绿标 task 已完成 |

分工贡献者不在各自半成品上重复运行最终build/lint/tests/formatters；TDD和最终验证责任由唯一集成负责人承担。需要委派修改时，先交付行为测试并由集成负责人取得预期RED，再交付实现并验证GREEN/REFACTOR，禁止提前实现掩盖RED。最终候选的完整门禁只运行一次并记录真实结果。

CI 应把 SQLite、PostgreSQL、Go/race、Vue 和关键 E2E 作为可识别必需结果；依赖服务不可用不能绿色通过，收集的套件/案例必须与计划一致。发布前另执行支持环境的恢复/外部集成/必要容量与 AI 评估，不能为了耗时把硬门禁改成“以后补测”。首次启用尚未具备这些环境时，如实保持未启用/未完成状态。

### 10.1 基础 CI（WOR-18）

入口为 `.github/workflows/ci.yml`，所有 PR（含后续提交）和推送到 `main` 时运行；不按路径过滤。同一 PR/分支的新运行取消旧运行。顶层仅授予 `contents: read`，checkout 不保留凭据，所有第三方 action 固定到 40 位 commit SHA 并注释版本。Go 版本读取 `go.mod`，Node 版本读取 `web/.nvmrc`，npm 依赖读取 `web/package-lock.json`。

| Job | 触发 | 检查 |
| --- | --- | --- |
| `go` | PR、main push | `go vet ./...` |
| `go-postgres` | PR、main push | `go test -p 2 -count=1 ./...`，同一次全量运行覆盖真实文件 SQLite WAL 和 PostgreSQL 17 |
| `web` | PR、main push | `npm ci`、`npm test -- --run`、`npm run build`（含 vue-tsc 类型检查） |
| `race` | 仅 main push | `go test -race -p 2 -count=1 ./...`，同样覆盖两库；独立 service container，与常规测试不共享数据库 |

现有全量 Go 测试强制要求 `TEAMLEDGER_TEST_POSTGRES_DSN`，缺失就失败。因此 SQLite 测试与 PostgreSQL 测试共用 `go-postgres`，不通过跳过 PostgreSQL 来制造独立 SQLite 绿灯。限制 package 并发为 2，避免并发迁移耗尽锁表。PostgreSQL 使用 service container，`.github/scripts/setup-postgres.sh` 每次生成短期 CA 与 localhost SAN 证书，TCP 强制 TLS，DSN 保留 `sslmode=verify-full` / `sslrootcert`。测试角色为非 superuser、非 BYPASSRLS，不授予 CREATEDB/CREATEROLE；仅拥有隔离测试数据库，测试按既有约定创建/清理独立 schema。`max_locks_per_transaction=1024`、`max_connections=200` 沿用已验证配置。容器内本地管理员仅用于测试初始化，不用于业务测试。

本地复现（Go/Node 版本同上述文件，需要 Docker 和 OpenSSL；只能对新建的一次性容器执行初始化）：

```bash
go vet ./...
ci_temp=$(mktemp -d)
ci_pg=$(docker run -d --rm -e POSTGRES_PASSWORD=synthetic-ci-admin \
  -e POSTGRES_DB=teamledger_test -p 127.0.0.1::5432 \
  --health-cmd='pg_isready -U postgres -d teamledger_test' \
  --health-interval=2s --health-timeout=5s --health-retries=30 \
  postgres:17-bookworm)
# 等待新容器的 health 为 healthy，再初始化 TLS（失败则检查 docker logs）。
docker inspect --format '{{.State.Health.Status}}' "$ci_pg"
RUNNER_TEMP="$ci_temp" GITHUB_ENV="$ci_temp/env" \
  bash .github/scripts/setup-postgres.sh "$ci_pg"
export TEAMLEDGER_TEST_POSTGRES_DSN="$(sed -n 's/^TEAMLEDGER_TEST_POSTGRES_DSN=//p' "$ci_temp/env")"
go test -p 2 -count=1 ./...
go test -race -p 2 -count=1 ./...
(cd web && npm ci && npm test -- --run && npm run build)
docker stop "$ci_pg"
rm -r "$ci_temp"
```

race 全量开销较大，默认在 main 上运行；合并前若改动并发逻辑，仍须本地执行并记录，不能以 PR 未自动运行替代原有门禁。基础 CI 不覆盖真实浏览器 E2E、生产部署、备份恢复或外部设施验收。首次接入以临时提交反转既有测试断言、观察 PR 报红、revert 并确认恢复全绿；实际 run 链接记录于 PR。

## 11. 每个开发 task 的 Definition of Done 与审查衔接

一个独立开发者/AI 只有在下列条件同时满足后，才能宣称 devtask 完成：

1. 指定端到端行为及所有受影响 acceptance 均有真实实现，所有调用点已迁移；没有 stub、mock-only 业务、明文 fallback、无用兼容别名、临时脚本或假数据接口残留。
2. RED/GREEN 可追溯，最终 tests 保护公开行为；bug 的修复前失败/修复后通过回归保留。REFACTOR 有实际记录或“无需重构”，不伪称执行。
3. 最终候选 revision 的第 10 节门禁实际执行；两数据库各自真实通过共享契约及适用方言/并发测试，程序/界面 smoke 完成；失败/skip/未测不冒充成功。依赖生产启用的外部服务、恢复或模型评估已满足该 task 范围要求，否则明确阻塞，不能假完成。
4. 本仓库整体最新功能与技术规范、相关PLAN/ADR/公开验证摘要和导航已更新，状态忠实区分拟实现、已接受、已实现与已验证；不能把文档更新留到task完成以后。
5. 代码和文档使用同一Task ID；引用必须指向本仓库真实文件、commit、PR或issue，未产生的引用不得编造。
6. 代码和文档同仓提交；候选确定后统一检查源码、测试、文档、链接和公开边界。任一部分未闭环，task仍保持执行中、审查中或阻塞。
7. 整体执行完成后，审查者检查PLAN、用户需求、行为测试、安全、双库和文档；发现修正后重新审查完整交付。测试步骤、分工和review自身不拆成递归交付task。
8. 记录实际审查范围、发现、处理理由和证据；审查不可用时如实标记阻塞，不能用主执行者自查冒充独立审查。
9. PLAN和公开验证摘要闭环、记录真实日期/结果/引用后才标已完成；不提交真实员工数据、凭据、密钥或敏感终端输出。
10. 验证、审查和文档闭环后，task commit必须实际push对应远端/分支；未推送保持待收尾或阻塞，不强推、绕过hook或混入无关文件；push不等于产品发布。


## 12. 来源与边界

下列来源均于 **2026-10-10** 查阅。工具资料只说明对应能力；业务规则、TDD门禁和审查要求是本项目约定，来源不是测试工具调用记录，也不是安全或法律合规保证。依赖版本以本仓库锁定版本为准；在线指南变化不自动改变已接受设计。

| 来源 | 支持的结论 | 适用限制 |
| --- | --- | --- |
| [Martin Fowler：Test Driven Development](https://martinfowler.com/bliki/TestDrivenDevelopment.html) | 列案例与 RED/GREEN/REFACTOR、接口导向 | TDD 定义/方法来源，不是 Go/Vue 官方强制要求，也不决定 HR 政策 |
| [Go：Add a test](https://go.dev/doc/tutorial/add-a-test) | `testing`、`_test.go`、`go test` 与错误案例 | 教程从已有代码添加测试；不得称其要求 TDD |
| [Go：Using Subtests and Sub-benchmarks](https://go.dev/blog/subtests) | table-driven、`t.Run`、选择案例与并行控制 | 说明能力，不免除隔离 fixture/实际数据库运行 |
| [Go：Data Race Detector](https://go.dev/doc/articles/race_detector) | `-race` 和只发现执行路径上的内存竞争 | 不能证明 DB 事务/锁/业务并发不变量；受平台/工具链约束 |
| [Go：Getting started with fuzzing](https://go.dev/doc/tutorial/fuzz) | seeds、属性式 fuzz、反例与修复 | 随机探索不等于穷尽验证；可用类型/平台按实际工具链确认 |
| [Vue3：Testing](https://vuejs.org/guide/scaling-up/testing.html) | Vitest、组件与 E2E 分层、公共行为、真实浏览器请求 | DOM 模拟不能证明浏览器布局/网络/生产部署，官方不要求数字覆盖目标 |
| [Vue Test Utils：A Crash Course](https://test-utils.vuejs.org/guide/essentials/a-crash-course.html) | mount、表单/事件操作、异步 DOM 与 AAA | 示例不决定本项目配置；本仓库实际runner和版本以`web/package.json`锁定 |
| [Vitest：CLI](https://vitest.dev/guide/cli.html) | `vitest run` 单次运行与 watch 区分 | 在线文档不是本次 Vue 执行证据；锁定实际采用版本 |
| [SQLite：Transaction](https://www.sqlite.org/lang_transaction.html) | 单 writer、DEFERRED/IMMEDIATE、BUSY 与回滚边界 | SQLite 事务不是 PostgreSQL 的替身，需真实连接验收 |
| [PostgreSQL：Transaction Isolation](https://www.postgresql.org/docs/18/transaction-iso.html) | Read Committed、多版本隔离、序列化失败等 | 按实际支持版本验收；设置隔离级别不自动满足业务约束 |
| [OWASP：Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) | 默认拒绝、每请求/对象服务端检查、授权单元/集成测试 | 自动 tests 不能取代独立安全测试；管理员/宿主威胁仍需设施与密钥边界设计 |
