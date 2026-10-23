# TeamLedger 文档

当前公开文档与源码统一在本仓库维护。

- [功能规范](FUNCTIONAL_SPEC.md)：功能模块、业务规则、页面、数据流、OP和AC。
- [技术规范](TECHNICAL_SPEC.md)：架构、数据模型、安全、身份、密钥、审计、部署和运行边界。
- [开发规则](DEVELOPMENT_RULES.md)：TDD、双数据库、安全测试、审查和交付门禁。
- [Docker安装与运维](../README.md#docker-安装与运维)：Linux/Windows首次安装、持久化、备份及维护。
- [DEV-024 public文档归并](plans/DEV-024.md)：迁移范围和验证状态。
- [DEV-024验证摘要](validation/DEV-024.md) · [双轮审查记录](reviews/DEV-024.md)
- [DEV-025统一产品UI](plans/DEV-025.md)：设计决定、实装范围和当前进度。
- [DEV-025验证摘要](validation/DEV-025.md) · [双轮审查记录](reviews/DEV-025.md)
- [DEV-026人员资料布局与无闪烁导航](plans/DEV-026.md)：问题、设计决定及task进度。
- [DEV-026验证摘要](validation/DEV-026.md) · [双轮审查记录](reviews/DEV-026.md)
- [DEV-027紧凑会话与安全面板](plans/DEV-027.md)：折叠交互、边界及进度。
- [DEV-027验证摘要](validation/DEV-027.md) · [双轮审查记录](reviews/DEV-027.md)
- [DEV-028全局查看日期与员工操作体验](plans/DEV-028.md)：全局日期、员工目录查询/分页及人员创建字段进度。
- [DEV-028验证摘要](validation/DEV-028.md) · [串行审查记录](reviews/DEV-028.md)
- [DEV-032人员资料批量上传](plans/DEV-032.md)：XLSX安全解析、逐行恢复与主管末段提交基线（字段范围已由DEV-033替代）。
- [DEV-032验证摘要](validation/DEV-032.md) · [审查记录](reviews/DEV-032.md)
- [DEV-033员工信息统一重构](plans/DEV-033.md)：完整员工主数据、18列模板、目录与详情统一字段。
- [DEV-033验证摘要](validation/DEV-033.md) · [审查记录](reviews/DEV-033.md)
- [DEV-038本地用户管理与首次改密](plans/DEV-038.md)：管理员固定安全权限、用户管理、首次改密及v14→v15迁移。
- [DEV-038验证摘要](validation/DEV-038.md)
- [DEV-039会话后台核对与文件上传连续性](plans/DEV-039.md)：focus核对不再刷新业务页或清除XLSX选择。
- [DEV-039验证摘要](validation/DEV-039.md)
- [DEV-040明确授权管理可用性修复](plans/DEV-040.md)：bootstrap安全grant读取、identity委派和管理筛选契约。
- [DEV-040验证摘要](validation/DEV-040.md)
- [DEV-041初始管理员全量可委派权限](plans/DEV-041.md)：38项当前可委派authority、v15→v16迁移及安全边界。
- [DEV-041验证摘要](validation/DEV-041.md)
- [DEV-042人员XLSX逐格错误诊断](validation/DEV-042.md)：最新模板经Excel保存后的类型兼容、sheet/cell错误和安全日志。
- [DEV-043 Staff关联账号与默认直属权限](plans/DEV-043.md)：standalone/staff账号类型、动态一层直属范围、员工资料与面谈最小默认权限及v16→v17迁移。
- [DEV-043验证摘要](validation/DEV-043.md)
- [DEV-044明确授权筛选界面重构](plans/DEV-044.md)：常用与高级条件分层、成对字段归组及桌面/移动端响应式布局。
- [DEV-044验证摘要](validation/DEV-044.md)
- [DEV-045人员XLSX日期兼容与错误透传](plans/DEV-045.md)：常见文本日期规范化、逐格错误preview及服务端request ID诊断。
- [DEV-045验证摘要](validation/DEV-045.md)
- [DEV-046人员XLSX语义兼容与可编辑预览](plans/DEV-046.md)：数字/文本工号、1900/1904日期、目录label解析、18字段重验及org级学历目录。
- [DEV-046验证摘要](validation/DEV-046.md)
- [DEV-047指定日期工资批量录入](plans/DEV-047.md)：Baseline批次、三列XLSX、服务端preview、不可变工资历史及v18→v19迁移。
- [DEV-047验证摘要](validation/DEV-047.md)
- [DEV-048人员导入可选字段与目录适配](plans/DEV-048.md)：可选学历/职位/职系/职级、现有目录下拉映射及未知目录显式创建。
- [DEV-048验证摘要](validation/DEV-048.md)
- [DEV-049 HOD Staff Code复合格式与同批次顺序无关的上级解析](plans/DEV-049.md)：`工号-姓名`规范化、本批次∪现有员工的主管校验、自我汇报/闭环阻断及两遍提交。
- [DEV-049验证摘要](validation/DEV-049.md)

历史私有计划、review会话、本机路径和旧文档commit台账不复制到public仓库；它们不是当前产品契约。当前行为以本仓库源码、迁移、永久测试和上述文档为准。
