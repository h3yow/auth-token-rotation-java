# Auth Token Rotation（访问令牌签发 / 轮换 / 撤销）

一个基于 Spring Boot 3 / Java 21 的内存态令牌服务，演示在**并发刷新、令牌重放与调用方限流**下，
鉴权结论如何保持**稳定、可解释、可复现**。

服务端保存每个令牌的状态（不使用无状态 JWT），因此撤销与重放判定可以**立即生效**，
而不是被动等待过期。

---

## 1. HTTP 接口

所有接口都必须携带调用方标识请求头 `X-Caller-Id`，它是限流与令牌归属判定的维度。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 签发会话与第一对令牌，请求体 `{"subject":"alice"}` |
| POST | `/api/auth/refresh` | 原子轮换，请求体 `{"refreshToken":"rtk_..."}`，旧刷新令牌立即失效并返回新令牌对 |
| POST | `/api/auth/logout` | 会话级注销，整条刷新链路与所有访问令牌立即失效 |
| POST | `/api/auth/resource` | 受保护资源，需 `Authorization: Bearer atk_...` |

成功响应（login / refresh）：

```json
{
  "accessToken": "atk_...",
  "refreshToken": "rtk_...",
  "familyId": "f1a2-...",
  "accessTokenExpiresAtMillis": 1700000300000,
  "refreshTokenExpiresAtMillis": 1700003600000
}
```

失败响应（统一 JSON）：

```json
{
  "error": "refresh_token_replay_concurrent",
  "message": "concurrent reuse of a refresh token detected",
  "callerId": "caller-A",
  "familyId": "f1a2-...",
  "tokenState": "ROTATED",
  "httpStatus": 401,
  "timestamp": "2026-09-26T04:00:00Z"
}
```

### 快速验证（curl）

```bash
BASE=http://localhost:8080

# 1) 登录
curl -s -X POST $BASE/api/auth/login -H 'X-Caller-Id: app-1' -H 'Content-Type: application/json' \
  -d '{"subject":"alice"}'

# 2) 访问资源
curl -s -X POST $BASE/api/auth/resource -H 'X-Caller-Id: app-1' -H "Authorization: Bearer $ATK"

# 3) 刷新轮换（旧 RTK 当场失效）
curl -s -X POST $BASE/api/auth/refresh -H 'X-Caller-Id: app-1' -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$OLD_RTK\"}"

# 4) 再次使用旧 RTK -> 401 refresh_token_replay_sequential，且整条链路被杀
curl -s -i -X POST $BASE/api/auth/refresh -H 'X-Caller-Id: app-1' -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$OLD_RTK\"}"

# 5) 注销 -> 未过期的访问令牌立刻不可用
curl -s -X POST $BASE/api/auth/logout -H 'X-Caller-Id: app-1' -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$RTK\"}"
```

---

## 2. 令牌生命周期

一次登录产生一个 **Session（会话）**，会话拥有一个 `familyId`。该次登录以及之后每次轮换
得到的所有刷新令牌与访问令牌都属于同一个 **family（刷新链路）**。

### 2.1 访问令牌（access token）

- 不透明高熵随机串（`atk_` + 256 bit，URL-safe Base64）。
- 默认 TTL **5 分钟**（`auth.security.access-token-ttl-millis`）。
- 状态随会话状态联动：访问时实时查询服务端记录与所属会话，因此撤销是即时的。

### 2.2 刷新令牌（refresh token）与轮换

- 不透明高熵随机串（`rtk_` + 256 bit）。
- 默认 TTL **60 分钟**（`auth.security.refresh-token-ttl-millis`）。
- 生命周期状态机：`ACTIVE -> ROTATED`（正常轮换）或任意状态 -> `REVOKED`（链路级失效）。
- 每次 `/refresh` 在**同一 family 的排他锁内原子地**完成：
  1. 校验调用方归属、会话状态、令牌状态与过期时间；
  2. 把当前刷新令牌从 `ACTIVE` 一次性翻转为 `ROTATED`（CAS 语义，只有一次成功）；
  3. 签发并持久化新的访问令牌 + 新的刷新令牌（新令牌沿用同一 `familyId`）。

### 2.3 重放检测（refresh token reuse detection）

除 family 锁外，还为每个 family 维护一个**单持有者闸门（gate）**，用于识别"并发重叠"：

- **并发重放** `refresh_token_replay_concurrent`：同一刷新令牌在一次轮换尚未结束时被再次出示
  （闸门仍开着、令牌已被赢家消耗）。并发齐发时恰好一个请求成功，重叠的输家得到该原因。
- **顺序重放** `refresh_token_replay_sequential`：一次轮换已经完整结束、闸门关闭后，
  旧令牌被再次出示（典型的令牌被盗后重放）。

> 说明：在真实线程调度下，一批同时发起的请求里，个别线程可能被操作系统调度得很晚，
> 在赢家关闭闸门之后才真正进入处理；此时它按"实际到达时刻"被如实归类为顺序重放。
> 两种原因都属于可区分的重放家族，安全结论完全一致。专门的确定性单测
> （`heldGateProducesConcurrentVerdict`）直接构造"闸门开 + 令牌已 ROTATED"状态，
> 精确覆盖并发分类路径。

### 2.4 重放的链路级后果（不是只拒绝单次）

一旦判定为任一种重放：

1. 整个 Session 被置为 `COMPROMISED`（终态，先到先得，不被后续注销覆盖）；
2. **赢家刚签发的新令牌对同样作废**——被盗链路上的所有后续刷新一律返回
   `chain_revoked_replay`；
3. 该 family 内所有尚未过期的访问令牌立即返回 `access_token_revoked_replay`；
4. **其它 family（其它会话 / 其它调用方）完全不受影响。**

---

## 3. 撤销与失效传播规则

| 触发动作 | 会话终态 | 未过期访问令牌 | 后续刷新 | 稳定原因码 |
|----------|----------|----------------|----------|------------|
| `/logout` | `LOGGED_OUT` | 立即不可用 | 一律拒绝 | `access_token_revoked_logout` / `chain_revoked_logout` |
| 检测到重放（并发/顺序） | `COMPROMISED` | 立即不可用 | 一律拒绝（含赢家新令牌） | `access_token_revoked_replay` / `chain_revoked_replay` |
| 重复注销已注销会话 | `LOGGED_OUT` | —— | —— | 幂等成功（日志 basis=`already_logged_out_idempotent`） |

实现要点：

- 访问令牌校验在**每次请求**时读取所属 Session 的状态，因此不存在"撤销黑名单延迟"，
  注销 / 重放判定后立即生效，不依赖访问令牌提前过期。
- 终态首次写入优先：`ACTIVE -> LOGGED_OUT / COMPROMISED` 单向迁移，
  重放结论不会被随后的注销掩盖，反之亦然，保证判定依据稳定可解释。

---

## 4. 调用方维度限流

- 维度：仅按请求头 `X-Caller-Id`（调用方身份）计数，**调用方之间互不影响**。
- 算法：**滑动窗口日志（sliding window log）**，按 key 加锁完成"淘汰旧时间戳 -> 计数 ->
  登记新请求"的原子操作，因此并发下不会漏放。
- 默认：每个调用方 **5 次 / 1000ms**
  （`auth.security.rate-limit-max-requests`、`auth.security.rate-limit-window-millis`）。
- 边界语义：窗口判定为 `(now - window, now]`。年龄**等于**窗口长度的旧请求会被淘汰，
  因此恰好在边界时刻到达的请求属于新窗口；同一时刻到期的多个时间戳会被一起淘汰
  （滑动窗口的确定性行为，测试已固定该结论）。被拒请求**不登记**，不会污染计数。
- 限流在鉴权之前执行，超限调用方无法继续探测令牌逻辑。
- 缺少调用方标识返回独立的 `caller_identity_missing`（400），与超限
  `rate_limit_exceeded`（429）可区分。

---

## 5. 稳定的判定原因码

| 原因码 | HTTP | 含义 |
|--------|------|------|
| `caller_identity_missing` | 400 | 缺少 `X-Caller-Id` |
| `rate_limit_exceeded` | 429 | 该调用方超出滑动窗口限额 |
| `access_token_missing` | 401 | 未携带 Bearer 令牌 |
| `access_token_unknown` | 401 | 服务端查无此令牌 |
| `access_token_caller_mismatch` | 401 | 出示者不是令牌归属调用方 |
| `access_token_expired` | 401 | 访问令牌已过期 |
| `access_token_revoked_logout` | 401 | 会话注销导致的即时失效 |
| `access_token_revoked_replay` | 401 | 重放判定导致的链路级失效 |
| `refresh_token_unknown` | 401 | 服务端查无此刷新令牌 |
| `refresh_token_caller_mismatch` | 401 | 出示者不是该链路归属调用方 |
| `refresh_token_expired` | 401 | 刷新令牌已过期 |
| `refresh_token_replay_sequential` | 401 | 闸门关闭后重用旧刷新令牌 |
| `refresh_token_replay_concurrent` | 401 | 与进行中的轮换并发重叠 |
| `chain_revoked_logout` | 401 | 已注销链路上的刷新尝试 |
| `chain_revoked_replay` | 401 | 已判定重放的链路上的后续刷新 |

每个被拒绝的请求都会打印一条结构化日志，包含**调用方标识、令牌状态、原因码与判定依据**，例如：

```
decision=refresh accepted=false callerId=app-1 familyId=f1a2 tokenState=ROTATED
  reason=refresh_token_replay_concurrent basis=gate_still_open_and_token_already_ROTATED
decision=rate_limit accepted=false callerId=app-1 tokenState=- reason=rate_limit_exceeded
  basis=sliding_window count=5 limit=5 window=[1700000000000,1700000001000] windowMs=1000
```

---

## 6. 验证方法（测试）

时间相关结论（过期、限流窗口）由测试中的 `MutableClock` 驱动，保证**确定性、可复现**，
不依赖 `sleep` 或真实时钟。

运行全部测试：

```bash
mvn test
```

| 测试类 | 覆盖内容 |
|--------|----------|
| `AuthServiceTest` | 登录、原子轮换、**顺序重放整条链失效**、**16 线程并发刷新恰好一次成功**、确定性并发分类、注销即时传播、family 隔离、过期原因、调用方不匹配 |
| `CallerRateLimiterTest` | 限额边界、**窗口边界（999ms 仍挡 / 1000ms 放行）**、调用方隔离、**50 线程并发只放行 5 个（无漏放）** |
| `AuthHttpIntegrationTest` | 真实 HTTP 全链路：登录/访问/轮换、**12 线程并发刷新**、注销后访问立即 401、缺调用方 / 跨调用方令牌 |
| `RateLimitHttpIntegrationTest` | 真实 HTTP 限流边界与跨调用方隔离（独立上下文，使用默认 5/1000ms 配置） |

并发刷新测试的**确定性断言**：成功数恰好为 1；所有失败请求的原因都属于可区分的
重放家族（并发 / 顺序 / 链路已失效），不存在任何"其它原因"；结束后整条链为 `COMPROMISED`。

测试日志（控制台 `System.out` 摘要 + SLF4J 明细）会打印调用方标识、令牌状态与判定依据，
形如：

```
[concurrent-refresh] callerId=caller-C threads=16 success=1 sequentialReplay=0
  concurrentReplay=1 chainRevoked=14 other=0 otherReasons=[]
[rate-limit-concurrency] callerId=caller-C threads=50 allowed=5 blocked=45
[http-rate-limit-boundary] callerId=rl-http-dave allowed=5 blocked=429x1 boundary=allowed
```

---

## 7. 配置项（`application.properties`）

```properties
auth.security.access-token-ttl-millis=300000      # 访问令牌 TTL
auth.security.refresh-token-ttl-millis=3600000    # 刷新令牌 TTL
auth.security.rate-limit-max-requests=5           # 每调用方每窗口最大请求数
auth.security.rate-limit-window-millis=1000       # 滑动窗口长度
```

## 8. 代码结构

```
domain/        Session(会话/family)、RefreshTokenRecord、AccessTokenRecord、TokenPair、AccessVerification
store/         TokenStore 接口与 InMemoryTokenStore（family 锁 + 单持有者闸门）
ratelimit/     CallerRateLimiter（按调用方的滑动窗口）与 RateLimitDecision
service/       AuthService（登录/轮换/重放/注销/校验核心）、TokenFactory、AuthErrorCode、AuthException
web/           AuthController、RateLimitInterceptor、ApiExceptionHandler、WebMvcConfig
config/        SecurityProperties
time/          Clock 抽象与 SystemClock（测试用 MutableClock 替换）
```
