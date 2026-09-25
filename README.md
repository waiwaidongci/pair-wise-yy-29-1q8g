# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换、轮换后的凭证续签换发和证件状态争议。

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
- `POST /api/credentials/{id}/renew`：密钥轮换后，持有人或签发方为未过期且无争议的旧凭证换发新版本。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 密钥轮换与续签

密钥轮换后，旧版本签出的未过期凭证进入续签宽限期（默认 30 天，见 `key_rules.RENEWAL_GRACE_DAYS`）：

- 截止前旧令牌验证结果为 `pending_renewal`（待续签）但仍有效，响应带 `renew_by` 截止时间；截止后验证拒绝，状态为 `renewal_overdue`。
- 持有人或签发方可调用续签接口换发新版本：新凭证沿用原声明与有效期、使用当前密钥签名；旧凭证置为 `superseded` 并写明失效时间（`renewal_invalid_at`，取凭证有效期与宽限截止的较早者）。
- 已换发的旧令牌在失效时间前仍可验证（`valid_until_supersession`），之后拒绝（`superseded`）。
- 同一旧凭证重复申请续签沿用首次结果（`reused: true`），由 `renewals` 表的唯一约束保证。
- 续签要求凭证未过期、未撤销、无未决争议且密钥已轮换；过期、撤销或争议中的凭证不能续签。

业务规则按职责拆分到三个文件：`key_rules.py`（密钥版本与宽限期规则）、`renewal.py`（续签资格判定与验证状态结论）、`renewal_store.py`（续签关系存储与凭证表结构迁移）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
