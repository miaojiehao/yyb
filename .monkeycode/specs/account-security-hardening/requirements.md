# 需求文档：账号安全加固与账号级 IP 绑定

## Introduction

YYB Go 微信账号管理服务当前无任何访问控制：后台无登录鉴权、无操作审计、无分级权限、无来源 IP 限制，仅适用于本地测试与内网环境。本需求为服务补齐第一层安全加固能力（管理后台登录鉴权、全量操作审计日志、分级权限、访问来源 IP 白名单），并实现核心扩展"账号级 IP 绑定"（每账号独立代理出口 + 账号级来源 IP 校验），从根源规避多账号共用出口 IP 触发的微信异地登录风控。

## Glossary

- **系统**: YYB Go 微信账号管理服务
- **管理员**: 拥有全部管理权限的用户
- **操作员**: 可执行账号读写与调用操作、不可管理系统配置与用户权限的用户
- **只读用户**: 仅可查看数据、不可执行任何变更操作的用户
- **微信账号（账号）**: `wechat_accounts` 表中登记的微信登录凭据
- **账号代理（bound_proxy）**: 绑定到单个微信账号的独立出口代理地址，格式 `socks5://host:port` 或 `http-connect://host:port`
- **账号来源 IP 白名单（allowed_source_ips）**: 绑定到单个微信账号的允许访问来源 IP 列表
- **审计日志**: 记录管理后台全部敏感操作事件的只追加日志

## Requirements

### Requirement 1: 管理后台登录鉴权

**User Story:** AS 管理员, I want 管理后台要求登录后才能访问, so that 未授权人员无法操作账号与调用接口

#### Acceptance Criteria

1. WHEN 系统启动且不存在任何用户, 系统 SHALL 使用 `--admin-password` 启动参数指定的密码创建默认管理员账号（用户名 `admin`）；若该参数未提供, 系统 SHALL 生成随机密码并输出到启动日志
2. WHEN 用户通过 `POST /auth/login` 提交正确的用户名与密码, 系统 SHALL 发放服务端会话，将会话标识写入 `Set-Cookie` 响应头，并在服务端会话存储中登记该会话
3. WHEN 用户访问除登录、健康检查、静态资源与二维码扫码确认以外的任何受保护路由且会话无效, 系统 SHALL 返回 HTTP 401 与 JSON 错误
4. WHEN 用户连续 5 次登录失败, 系统 SHALL 锁定该用户名 30 分钟并在登录响应中返回剩余锁定时间
5. WHEN 用户点击退出登录, 系统 SHALL 删除服务端会话并使当前 Cookie 立即失效
6. 系统 SHALL 使用 bcrypt 算法存储用户密码哈希, 日志与 API 响应中不得出现明文密码

### Requirement 2: 全量操作审计日志

**User Story:** AS 管理员, I want 所有敏感操作都被记录, so that 任何变更可追溯责任人

#### Acceptance Criteria

1. WHEN 任何已认证用户执行以下操作, 系统 SHALL 追加一条审计日志：登录成功、登录失败、退出登录、创建/删除账号、刷新/重扫账号、修改账号代理、修改账号 IP 白名单、调用 wxapp 接口、创建/删除用户、修改用户权限、修改系统配置
2. 每条审计日志 SHALL 包含：时间戳、操作者、动作、目标类型、目标标识、执行结果、来源 IP、请求详情摘要
3. WHEN 管理员调用审计日志查询接口, 系统 SHALL 按时间倒序返回日志, 并支持按操作者、动作、时间段过滤与分页
4. 审计日志 SHALL 以只追加方式写入独立的 `audit_logs` 表, 已有日志不得被修改或删除

### Requirement 3: 账号操作权限划分

**User Story:** AS 管理员, I want 不同用户拥有不同操作权限, so that 低权限用户无法执行敏感操作

#### Acceptance Criteria

1. 系统 SHALL 支持三类角色：管理员、操作员、只读用户
2. WHEN 操作员调用账号调用（getCode / getPhoneNumber / operateWxData）、刷新、重扫、删除接口, 系统 SHALL 允许执行
3. WHEN 操作员调用用户管理或系统配置接口, 系统 SHALL 返回 HTTP 403 拒绝执行
4. WHEN 只读用户调用任何变更类接口（POST / DELETE）, 系统 SHALL 返回 HTTP 403 拒绝执行
5. 系统 SHALL 在登录时加载用户角色, 每个受保护操作由服务端中间件校验角色, 前端隐藏不等于服务端拒绝

### Requirement 4: 全局访问来源 IP 白名单

**User Story:** AS 管理员, I want 限制管理后台的访问来源, so that 仅允许的 IP 段能连接服务

#### Acceptance Criteria

1. 系统配置 SHALL 提供可选的全局 IP 白名单（支持 CIDR 与单 IP）
2. WHEN 全局白名单启用且客户端来源 IP 不在白名单内, 系统 SHALL 对除健康检查以外的所有路由返回 HTTP 403
3. WHEN 全局白名单未启用或为空, 系统 SHALL 放行所有来源 IP
4. 系统 SHALL 从可信代理头（如 `X-Forwarded-For` / `X-Real-IP`）或直接连接地址中解析客户端真实来源 IP

### Requirement 5: 账号级出口代理绑定（bound_proxy）

**User Story:** AS 管理员, I want 为每个账号绑定独立出口代理 IP, so that 微信侧识别 IP 与账号常用地区匹配、规避异地登录风控

#### Acceptance Criteria

1. `wechat_accounts` 表 SHALL 新增 `bound_proxy` 字段, 格式支持 `socks5://host:port` 与 `http-connect://host:port`
2. WHEN 账号存在 `bound_proxy` 配置, 系统 SHALL 在调用该账号的 wxapp 接口（getCode / getPhoneNumber / operateWxData）与刷新、重扫操作时优先使用该代理建立连接
3. WHEN 账号 `bound_proxy` 为空, 系统 SHALL 回退使用全局代理配置, 全局代理也为空时使用直连
4. 系统 SHALL 依据账号代理隔离会话, 同一账号使用不同代理时 SHALL 复用已有的 `sessions` 表 `(wechat_account_id, tcp_proxy)` 唯一键机制, 不产生额外会话存储
5. WHEN 管理员通过接口或控制台更新账号 `bound_proxy`, 系统 SHALL 使该账号在该代理下的既有会话失效并记录审计日志

### Requirement 6: 账号级来源 IP 白名单（allowed_source_ips）

**User Story:** AS 管理员, I want 限制每个账号的调用来源 IP, so that 非授权 IP 无法使用该账号

#### Acceptance Criteria

1. `wechat_accounts` 表 SHALL 新增 `allowed_source_ips` 字段, 支持 JSON 数组或逗号分隔格式
2. WHEN 账号存在 `allowed_source_ips` 且客户端来源 IP 不在列表内, 系统 SHALL 对该账号的所有调用、刷新、重扫与删除请求返回 HTTP 403
3. WHEN 账号 `allowed_source_ips` 为空或未配置, 系统 SHALL 放行该账号的所有来源 IP
4. 系统 SHALL 支持 CIDR 与单 IP 两种匹配形式
5. WHEN 管理员更新账号 `allowed_source_ips`, 系统 SHALL 记录审计日志

## Out of Scope（本期不实施）

- 第二层：调用链路可视化监控、请求失败自动重试机制
- 第三层：账号分组/标签管理、调用记录查询与数据导出、批量账号健康状态检测、凭据失效批量重扫提醒
- 账号级绑定的代理认证（需要认证的 SOCKS5/HTTP 代理）
- 基于角色的前端路由级菜单权限（仅服务端校验 + 前端按需隐藏）
