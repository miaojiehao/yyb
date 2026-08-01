# 需求实施计划

- [x] 1. 扩展数据访问层（internal/store）
  - [x] 1.1 实现 wechat_accounts 迁移，幂等新增 bound_proxy 与 allowed_source_ips 列（PRAGMA table_info 判断存在性）
  - [x] 1.2 在 schema 中新增 admin_users 与 audit_logs 表及索引（设计文档 Data Models）
  - [x] 1.3 扩展 WechatAccount 结构体新增 BoundProxy / AllowedSourceIPs 字段，同步更新 selectAccountSQL 与 scanAccountRows
  - [x] 1.4 实现用户管理方法 GetUser / GetUserByName / CreateUser / DeleteUser / SetUserRole / SetUserPassword / UpdateUserLoginMeta
  - [x] 1.5 实现审计 AppendAudit / QueryAudit（按操作者、动作、时间段过滤 + 分页 + 倒序）
  - [x] 1.6 实现 GetAccountConfig / SetAccountConfig（bound_proxy 与 allowed_source_ips 一起更新）与 SetAccountProxy
  - [x] 1.7 编写 store 单元测试：迁移幂等性（老库加列/新库建表）、配置字段读写、audit 追加与查询

- [x] 2. 实现认证与会话包（internal/auth）
  - [x] 2.1 实现 Session 结构体与会话 Manager（crypto/rand 生成 ID、存哈希、Create/Get/Delete/Renew、互斥锁）
  - [x] 2.2 实现 bcrypt 密码哈希 Hash / Verify
  - [x] 2.3 实现登录失败锁定：failed_attempts 累计、连续 5 次锁定 30 分钟、锁定期间拒绝登录
  - [x] 2.4 实现 AuthMiddleware 与公开路径集合判断，会话无效返回 401，成功注入当前用户上下文
  - [x] 2.5 实现 RequireRole 角色校验中间件（admin/operator/viewer），不匹配返回 403
  - [x] 2.6 编写 auth 单元测试：登录成功/失败/锁定/解锁、会话创建校验删除续期、bcrypt 校验

- [x] 3. 实现来源 IP 白名单包（internal/ipfilter）
  - [x] 3.1 实现 Matcher：编译单 IP 与 CIDR 列表，Allow 匹配方法
  - [x] 3.2 实现 ClientIP 解析：X-Forwarded-For 首项、X-Real-IP、RemoteAddr 兜底
  - [x] 3.3 实现全局白名单中间件：非空即启用、/health 放行、其余校验失败返回 403
  - [x] 3.4 编写 ipfilter 单元测试：单 IP / CIDR / 端口剥离 / XFF 解析 / 空列表放行

- [x] 4. 实现审计日志包（internal/audit）
  - [x] 4.1 定义 Entry 结构体与动作枚举（login_success、account_delete、wxapp_call、user_create 等）
  - [x] 4.2 实现 Append / Query 封装，接入 store.AppendAudit / QueryAudit

- [x] 5. 检查点：确保 go build 与现有 store_test / app_test 通过，如有疑问请询问用户

- [x] 6. 集成 httpapi 安全能力与路由
  - [x] 6.1 注册中间件链（全局 IP 白名单 → 认证 → 路由），定义受保护与公开路径，docs/openapi 纳入保护
  - [x] 6.2 实现登录 / 登出 / auth/me handlers（登录成功 Set-Cookie、写审计、失败计数与锁定）
  - [x] 6.3 实现用户管理 handlers：GET/POST /auth/users、DELETE /auth/users/:id、POST /auth/users/:id/role、POST /auth/password（仅 admin 管理用户，人人可改自己密码）
  - [x] 6.4 实现审计日志查询 handler GET /audit/logs（仅 admin）
  - [x] 6.5 实现账号配置 GET/POST /accounts/:ref/config（校验代理格式复用 parseTCPProxy、IP 列表格式）
  - [x] 6.6 账号代理接入调用链：invokeWXApp / invokeGetCode / invokeGetPhoneNumber / invokeOperateWXData 使用 effectiveAccountProxy（账号代理优先，回退全局），refresh / resync 同步接入
  - [x] 6.7 更新 bound_proxy 时使该账号旧代理会话失效
  - [x] 6.8 账号级白名单校验：账号解析成功后校验 allowed_source_ips，不匹配返回 403
  - [x] 6.9 敏感操作审计埋点：登录、账号删除/刷新/重扫、配置更新、wxapp 调用、用户管理
  - [x] 6.10 编写 httpapi 集成测试（gin httptest）：未认证 401、viewer 变更 403、operator 用户管理 403、账号级白名单命中/未命中、登录后 Cookie 访问全链路

- [x] 7. main.go 启动配置
  - [x] 7.1 新增 --admin-password 与 --allowed-ips flag
  - [x] 7.2 启动时初始化 admin 用户（已存在则忽略）与全局白名单配置，未提供密码时生成随机密码打印到日志

- [x] 8. 前端控制台改造（resource/templates/index.html）
  - [x] 8.1 实现登录视图与 401 统一跳转处理
  - [x] 8.2 顶栏新增当前用户信息与退出登录
  - [x] 8.3 账号详情面板新增绑定代理与来源 IP 白名单配置输入框并提交到 /accounts/:ref/config
  - [x] 8.4 管理员面板：用户列表与角色管理、审计日志查询表格

- [x] 9. 检查点：编译并重新部署，验证登录鉴权 / 角色 / 代理回退 / 白名单 / 审计全流程，如有疑问请询问用户
