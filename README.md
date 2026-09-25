# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/renew`：密钥换版后，持有人或签发方为旧版本凭证续签换发。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 续签流程

密钥轮换（换版）时，退役密钥会记录续签截止 `renewal_deadline`（默认退役后 30 天，见 `keys.RENEWAL_GRACE_DAYS`）。旧版本签出的凭证在此窗口内待续签：

- 截止前，旧令牌验证返回 `pending_renewal`（仍有效，附带 `renewal_deadline`）；截止后返回 `renewal_overdue` 并被拒绝。
- 持有人（`holder`）或签发方（`issuer`）可对未过期、无争议且非当前密钥版本的凭证调用 `POST /api/credentials/{id}/renew`：换发当前密钥版本的新凭证（沿用声明，有效期重算），旧凭证置为 `superseded` 并写明失效时间 `superseded_at`，续签关系写入 `renewals` 表并出现在 `GET /api/state` 中。
- 同一旧凭证重复申请续签沿用首次结果（响应 `replayed: true`），并发重复申请亦然。
- 换发后旧令牌验证返回 `superseded`，附带失效时间与 `replaced_by` 新凭证编号；按失效时间之前的历史时间点验证仍按当时状态判定。

## 代码结构

- `common.py`：时间、规范化 JSON 与 `ApiError` 等共享基础。
- `store.py`：SQLite 模式、轻量迁移、行映射与审计日志（存储）。
- `keys.py`：密钥轮换、当前版本查询与续签宽限规则（密钥规则）。
- `renewal.py`：续签资格判定、续签关系与验证状态结论（续签判定）。
- `app.py`：HTTP 接口与签发、验证等流程编排。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
