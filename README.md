# Auth Token Rotation（访问令牌签发 / 轮换 / 撤销 / 调用方限流）

基于 Spring Boot 3.4 / Java 21 的进程内实现，目标是让**并发刷新、令牌重放、调用方限流**
三类场景下的鉴权结论稳定、可解释、可复现：

- 每次判定都对应一个稳定、可区分的错误码（见下表），HTTP 响应体固定返回
  `{"error": "...", "reason": "...", "timestamp": "..."}`；
- 刷新链路（family）级别的"读-判-写"在同一锁段内原子完成；
- 限流按调用方身份（`clientId`）独立计数，使用滑动窗口日志算法；
- 测试注入固定起点的可拨动时钟（`MutableClock`），时间相关结论不依赖墙钟，完全可复现。

## 1. HTTP 接口

| 方法 | 路径 | 说明 | 关键请求头 / 请求体 |
| --- | --- | --- | --- |
| POST | `/auth/login` | 用户名口令登录，签发令牌对 | `X-Client-Id`；JSON `{username, password}` |
| POST | `/auth/refresh` | 刷新轮换，旧刷新令牌原子失效并返回新令牌对 | `X-Client-Id`、`Authorization: Bearer <refreshToken>` |
| POST | `/auth/logout` | 会话级注销，链路撤销并传播 | `X-Client-Id`、`Authorization: Bearer <accessToken>` |
| GET  | `/api/ping` | 受保护资源示例（先鉴权后限流） | `Authorization: Bearer <accessToken>` |

演示口令固定为 `password`（见 `DefaultAuthService.DEMO_PASSWORD`），生产环境应替换为
凭据库与口令哈希校验。

令牌为不透明随机串，编码其所属链路：

- 访问令牌：`atk.<familyId>.<tokenId>`
- 刷新令牌：`rtk.<familyId>.<tokenId>`

其中 `tokenId` 为服务端不可猜测的随机标识，真实状态只保存在服务端。

## 2. 令牌生命周期

配置项（`application.properties`，均为 `java.time.Duration` 格式）：

| 配置 | 默认值 | 含义 |
| --- | --- | --- |
| `auth.token.access-ttl` | `PT5M` | 访问令牌有效期 |
| `auth.token.refresh-ttl` | `PT30M` | 刷新令牌有效期，每次轮换后按 TTL 重新计时 |
| `auth.token.replay-grace-window` | `PT2S` | 区分"并发竞争"与"重放攻击"的宽限窗口 |
| `auth.ratelimit.max-requests` | `10` | 每个调用方在一个滑动窗口内的最大请求数 |
| `auth.ratelimit.window` | `PT10S` | 限流滑动窗口时长 |

生命周期要点：

1. **签发**：登录成功创建一条刷新链路（family，与会话一一对应），返回访问令牌 + 刷新令牌。
2. **轮换**：刷新成功时，当前刷新令牌立即进入"已消费"集合，服务端原子生成新一代
   刷新令牌与新的访问令牌；旧令牌对的调用方应丢弃旧令牌。
3. **过期**：访问令牌过期返回 `ACCESS_TOKEN_EXPIRED`；刷新令牌过期返回
   `REFRESH_TOKEN_EXPIRED`。过期只影响单次判定，不撤销链路。

## 3. 并发刷新与重放判定（可区分原因）

同一刷新令牌被并发或重复提交时，结论由"令牌代际 + 宽限窗口"共同决定，
判定全程持有该 family 的原子锁（`ConcurrentHashMap.compute`），因此结论不依赖
线程调度顺序：

| 场景 | 判定错误码 | 链路处理 |
| --- | --- | --- |
| 持当前（最新一代）刷新令牌正常刷新 | HTTP 200，返回新令牌对 | 原子轮换到下一代 |
| 多个请求同时使用同一刷新令牌 | 恰好 1 个成功；其余 `REFRESH_CONCURRENT_RACE` | **不撤销**，合法会话继续可用 |
| 最近一次轮换刚失效的那一代令牌，在宽限窗口内被再次使用 | `REFRESH_CONCURRENT_RACE` | **不撤销**（视为并发/双击重复提交） |
| **更早代际**的已消费令牌再次出现（即使仍在宽限窗口内） | `REFRESH_REPLAY_DETECTED` | **整条链路立即撤销** |
| 最近一代被消费令牌在宽限窗口外再次使用 | `REFRESH_REPLAY_DETECTED` | **整条链路立即撤销** |
| 链路已撤销后再使用其任意刷新令牌 | `REFRESH_FAMILY_REVOKED` | 维持撤销 |
| 令牌无法解析或查无此链路 | `REFRESH_TOKEN_UNKNOWN` | 不变 |

设计含义：

- "并发落败"与"重放"是**两个不同错误码**，调用方与测试可以稳定区分；
- family 之间使用各自独立的锁段，一条链路的竞争或重放不会阻塞或误伤其他会话；
- 重放检测遵循 OAuth Refresh Token Rotation 的"重放即撤销全家桶"语义：一旦判定，
  该链路所有代际的刷新令牌与所有未过期访问令牌同时失效。

## 4. 撤销与失效传播

两类撤销都会**同步**传播，无需等待访问令牌自然过期：

1. **显式注销**（`POST /auth/logout`）：family 标记撤销，该 family 下所有访问令牌
   立即标记失效。随后即使令牌尚未过期，访问 `/api/**` 也返回 `SESSION_REVOKED`。
2. **重放撤销**：见上节，重放判定在同一原子锁段内完成 family 撤销与访问令牌批量失效。

访问 `/api/**` 的服务端校验顺序为：

1. 令牌存在且可解析 → 否则 `ACCESS_TOKEN_MISSING` / `ACCESS_TOKEN_UNKNOWN`；
2. 访问令牌未被单独标记撤销 → 否则 `SESSION_REVOKED`；
3. 所属 family 未撤销 → 否则 `SESSION_REVOKED`（注销/重放的即时传播点）；
4. 未超过 `expiresAt` → 否则 `ACCESS_TOKEN_EXPIRED`。

## 5. 限流维度与边界语义

- 限流维度是**调用方身份 `clientId`**：
  - `/auth/**`：身份取自请求头 `X-Client-Id`（缺失返回 `CLIENT_ID_MISSING`）；
  - `/api/**`：请求先经过访问令牌鉴权，限流身份取自**服务端令牌绑定的 clientId**。
    调用方伪造 `X-Client-Id: someone-else` 不会改变限流归属，无法借用他人配额或嫁祸他人。
- 算法为**滑动窗口日志**：每个 clientId 维护窗口内请求时间戳，判定前先剔除窗口外
  旧时间戳，再与配额比较。时间窗边界附近：
  - 窗口内请求数严格不超过配额，不会**漏放**；
  - 旧请求离开窗口后配额精确恢复，不会**误伤**；
  - 同一 clientId 的计数在独立锁段内更新，并发请求不会突破配额。
- 不同 clientId 的窗口状态完全隔离，互不影响。
- 超限请求返回 HTTP `429` 与错误码 `RATE_LIMITED`（其他鉴权失败为 HTTP `401`）。

过滤器顺序：`ClientRateLimitFilter(/auth/**, order=10)` →
`AccessTokenAuthenticationFilter(/api/**, order=20)` →
`ApiRateLimitFilter(/api/**, order=30)`。

## 6. 错误码一览

| 错误码 | HTTP | 含义 |
| --- | --- | --- |
| `LOGIN_INVALID` | 401 | 用户名或密码错误 |
| `ACCESS_TOKEN_MISSING` | 401 | 缺少访问令牌 / Authorization 头 |
| `ACCESS_TOKEN_UNKNOWN` | 401 | 访问令牌无法解析或不存在 |
| `ACCESS_TOKEN_EXPIRED` | 401 | 访问令牌已过期 |
| `SESSION_REVOKED` | 401 | 会话注销或链路重放撤销，访问令牌立即失效 |
| `REFRESH_TOKEN_MISSING` | 401 | 缺少刷新令牌 |
| `REFRESH_TOKEN_UNKNOWN` | 401 | 刷新令牌无法解析、不存在或归属不符 |
| `REFRESH_TOKEN_EXPIRED` | 401 | 刷新令牌已过期 |
| `REFRESH_CONCURRENT_RACE` | 401 | 同一刷新令牌并发/重复使用，本次落败（链路保留） |
| `REFRESH_REPLAY_DETECTED` | 401 | 检测到旧刷新令牌重放，链路已整体撤销 |
| `REFRESH_FAMILY_REVOKED` | 401 | 刷新链路此前已因重放/注销被撤销 |
| `RATE_LIMITED` | 429 | 超过该调用方滑动窗口请求上限 |
| `CLIENT_ID_MISSING` | 401 | 缺少 `X-Client-Id`，无法进行身份维度判定 |

## 7. 如何验证

```bash
mvn test
```

测试为随机端口的全栈集成测试（JDK 内置 `HttpClient`），时钟固定在
`2026-09-26T00:00:00Z` 并可在测试中拨动，覆盖：

- `ConcurrentRefreshIntegrationTest`：8 线程并发刷新同一令牌，断言**恰好 1 次成功、
  7 次 `REFRESH_CONCURRENT_RACE`、0 次重放误判**；并验证其他会话的访问与刷新不受影响。
- `RefreshReplayAndRevocationIntegrationTest`：多代轮换链、宽限窗口内竞争落败、
  更早代际重放（即使在窗口内也确定性撤销全家桶）、时间窗边界重放、注销后未过期
  访问令牌立即失效、访问令牌过期但刷新链路仍可用、非法令牌原因可区分。
- `RateLimitIntegrationTest`：窗口内恰好放行 N 次第 N+1 次 429、滑动边界逐一释放配额、
  20 并发下放行数恰好等于配额、不同 clientId 隔离、`/api` 限流身份以令牌绑定为准。

每次请求与判定都会在日志中打印**调用方标识、令牌（脱敏）状态与判定依据**，例如：

```
刷新成功（轮换） | clientId=client-replay | sessionId=... | 旧refreshTokenId=... | 新refreshTokenId=... | 判定依据=当前刷新令牌，原子轮换
刷新拒绝（并发竞争落败） | clientId=... | 竞争refreshTokenId=... | 距上次轮换=100ms | 宽限窗口=500ms | 判定依据=最新一代刷新令牌在宽限窗口内被并发重复使用
刷新拒绝（重放检测，链路整体撤销） | ... | 最新代际=false | 撤销访问令牌数=3 | 判定依据=更早代际的已消费刷新令牌被再次使用...
访问拒绝 | clientId=... | accessTokenId=... | 状态=已撤销 | 判定依据=访问令牌已被会话注销/重放撤销
限流命中 | clientId=... | 当前窗口计数=5 | 上限=5 | 判定依据=窗口内请求数已达上限
[TEST 请求] 场景=刷新 | clientId=... | refreshToken=rtk... | token状态=被拒绝(REFRESH_CONCURRENT_RACE) -> HTTP 401 ...
```

手动验证示例：

```bash
BASE=http://localhost:8080
curl -s -X POST "$BASE/auth/login" -H "X-Client-Id: demo" -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password"}'
# 用返回的 refreshToken 连续刷新两次：第一次 200，第二次 401/REFRESH_CONCURRENT_RACE；
# 等待超过宽限窗口后再用更旧的 refreshToken：401/REFRESH_REPLAY_DETECTED，且新令牌全部失效。
```

## 8. 关键类索引

- `domain/TokenFamily`：刷新链路状态（当前代际、已消费令牌代际、撤销标记）。
- `domain/RotationOutcome`：family 锁段内得出的原子结论（成功/竞争/重放/其他拒绝）。
- `store/InMemoryTokenStore`：per-family 原子锁（`ConcurrentHashMap.compute`）与访问令牌索引。
- `service/DefaultAuthService`：签发、轮换、重放判定、注销传播、访问鉴权。
- `service/ClientRateLimiter`：per-client 滑动窗口限流器。
- `security/*Filter`：`/auth/**` 限流、`/api/**` 鉴权、`/api/**` 可信身份限流。
- `security/GlobalExceptionHandler` / `FilterResponses`：稳定错误响应。
