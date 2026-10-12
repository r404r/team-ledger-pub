# TeamLedger

- [DEV-002 实装、测试与进度 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-002.md)
- [功能规范](https://github.com/r404r/p-research-hr/blob/main/docs/FUNCTIONAL_SPEC.md) · [技术规范](https://github.com/r404r/p-research-hr/blob/main/docs/TECHNICAL_SPEC.md)
- [开发与交付规则](https://github.com/r404r/p-research-hr/blob/main/AGENTS.md)
- [DEV-006 OIDC、会话/MFA、映射维护与 v4 操作者/目标分离实装测试 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-006.md) · [身份协议/时序与实际保护配置/CLI](https://github.com/r404r/p-research-hr/blob/main/docs/TECHNICAL_SPEC.md#71-oidcsession与step-up)
- [DEV-007 当前 R2 组织结构、原子任职/生命周期变更、人员目录/历史、当前精确关系授权与 v5 双库 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-007.md) · [实际 API/production 页面、迁移/授权/隐私与测试证据](https://github.com/r404r/p-research-hr/blob/main/research/hr-implementation/DEV-007-VALIDATION.md)；技术架构图在技术规范 §1.1/§1.2，R2 HTTP 契约 §3.4、原子变更时序 §6.3.1、保护 CLI §9.3。
- [DEV-008 当前 R3 面谈、immutable 三分区版本、独立行动、typed 最小交接与有限导出 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-008.md) · [实际双库/成品与测试证据](https://github.com/r404r/p-research-hr/blob/main/research/hr-implementation/DEV-008-VALIDATION.md)；R3 HTTP 窄契约见技术规范 §3.5、独立批准/版本/导出 Mermaid 时序 §6.4.1、必需独立 `TEAMLEDGER_INTERVIEW_KMS_*` 配置 §9.3。不复用 PII key/credential；API 不自动迁移，生产 IdP/MFA/读者/保留批准另验。
- [DEV-011 评估周期、确定性完成事实与 AI 边界 PLAN](https://github.com/r404r/p-research-hr/blob/main/plans/DEV-011.md)：R6a 提供 `PUT /api/v1/employees/{employee_id}/interview-policy` 与 `GET /api/v1/employees/{employee_id}/interview-status`、`/employees/{employee_id}/followup` 成品页面及 SQLite/PostgreSQL v9。状态仅来自计划窗口、面谈实际时间、已发布共享笔记与行动项；`periodic_structured_v1` 在 R6a 明确返回 `blocked/automation_not_enabled`，不调用模型或伪装后台自动化。
