# WOR-18：基础持续集成

日期：2026-10-23。状态：实现与验证中，待独立审查；不合并 PR。

范围：新增 PR / main 推送的 Go 静态检查、真实 SQLite WAL 与 PostgreSQL 17 全量测试、Web 测试与类型检查/构建，以及 main 的双库 race 检查。关联 F-DB-001 / F-SEC-001 的既有回归入口，不改变业务、授权、schema 或迁移。

实施前检查：当前根目录没有 tracked `AGENTS.md`；依据开发规则和现有测试契约实施。Go 全量测试缺少 `TEAMLEDGER_TEST_POSTGRES_DSN` 会失败，不能拆成无 PostgreSQL 的全量 SQLite job。`go` 负责 vet，`go-postgres` 执行包含两库的完整套件。TLS 保留 verify-full，测试角色无 superuser / BYPASSRLS，独立 schema 自动清理；锁容量采用既有验证的 1024。

交付：SHA 固定的最小权限 workflow、可本地复用的隔离 PostgreSQL TLS 初始化脚本、Node 版本文件和开发规则中的触发/复现说明。

验证：`actionlint`、`bash -n`、`go vet ./...`、`go test -p 2 -count=1 ./...`、`go test -race -p 2 -count=1 ./...`、`npm ci`、`npm test -- --run`、`npm run build`。数据库环境由专用 PostgreSQL 17 service container 提供，每次生成短期合成 CA/server certificate；无生产数据或凭据。临时提交故意反转现有行为断言，确认 PR 检查报红后 revert，记录失败与恢复 run。

审查：实现 PR 交付后进入独立代码与安全审查，合并由维护者决定。基础 CI 不涵盖浏览器 E2E、备份恢复、外部身份/密钥设施或生产启用验收。
