# Auth Token Rotation（访问令牌签发 / 轮换 / 撤销 / 回收）

一个基于 Spring Boot 3 / Java 21 的内存态令牌服务。服务端保存每个令牌的状态（不使用无状态 JWT），
因此撤销、重放判定与容量回收都可以**立即、确定地生效**，而不是被动等待过期。

本版本在上一轮「能演示」的基础上，补齐长期稳定运行所需的三块能力，并保持各类结论彼此可区分：

1. **并发刷新的稳定结论**：同一刷新凭证被一批并发请求同时换新时，与线程调度无关地
   「恰好一次成功、其余全部得到同一个并发冲突结论」，良性并发**不误伤链路**；只有在这轮换新
   彻底结束并越过重叠窗口之后再拿旧凭证来用，才算真正的事后重放并让链路失效。
2. **限流身份以服务端认定为准**：配额只按「服务端凭证归属」计费，伪造 `X-Caller-Id`、
   拿无效凭证来刷，既不消耗任何真实调用方额度，自身也拿到可区分的拒绝结论。
3. **可控容量回收**：注销 / 判死 / 自然过期后彻底无用的数据可安全清理，可在并发访问进行时触发，
   不误删有效会话，边界判定与鉴权完全一致，并有按类别统计的可观测结果。

---

## 1. HTTP 接口

所有业务接口都携带调用方标识请求头 `X-Caller-Id`。**注意：该头是「声明身份」，不是限流信任来源**
（见第 4 节）；登录时它只作为新会话的归属标签。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 签发会话与第一对令牌，请求体 `{"subject":"alice"}`（无凭证，计入**未认证**桶） |
| POST | `/api/auth/refresh` | 原子轮换，请求体 `{"refreshToken":"rtk_..."}`（按凭证归属调用方计费） |
| POST | `/api/auth/logout` | 会话级注销，整条链路与所有访问令牌立即失效（按凭证归属计费） |
| POST | `/api/auth/resource` | 受保护资源，需 `Authorization: Bearer atk_...`（按凭证归属计费） |
| POST | `/api/auth/maintenance/reclaim` | 触发一次安全回收，返回按类别统计的回收报告（计入**未认证**运维桶） |

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

并发冲突响应（良性，HTTP **409**，链路不受影响，客户端应丢弃手中旧凭证、改用赢家新凭证或重试）：

```json
{
  "error": "refresh_concurrent_conflict",
  "message": "concurrent use of the same refresh token; exactly one attempt wins and the chain is preserved",
  "callerId": "app-1",
  "familyId": "f1a2-...",
  "tokenState": "ROTATED",
  "httpStatus": 409,
  "timestamp": "2026-10-08T04:00:00Z"
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

# 4) 轮换结束后立刻再用旧 RTK -> 409 refresh_concurrent_conflict（仍在重叠窗口内，良性并发，不杀链）
curl -s -i -X POST $BASE/api/auth/refresh -H 'X-Caller-Id: app-1' -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$OLD_RTK\"}"

# 5) 越过重叠窗口（默认 2000ms）后再用旧 RTK -> 401 refresh_token_replay_sequential，整条链路判死
#    （本地用默认时钟时 sleep 2.1 秒即可；自动化测试用 MutableClock 精确驱动）
sleep 3
curl -s -i -X POST $BASE/api/auth/refresh -H 'X-Caller-Id: app-1' -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$OLD_RTK\"}"

# 6) 注销 -> 未过期的访问令牌立刻不可用
curl -s -X POST $BASE/api/auth/logout -H 'X-Caller-Id: app-1' -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$RTK\"}"

# 7) 触发回收 -> 返回各类别扫描/删除数量
curl -s -X POST $BASE/api/auth/maintenance/reclaim -H 'X-Caller-Id: ops'
```

---

## 2. 令牌生命周期与并发刷新判定

一次登录产生一个 **Session（会话）**，拥有一个 `familyId`；该会话及之后每次轮换的所有令牌同属一个
**family（刷新链路）**。

### 2.1 刷新令牌状态机

```
ACTIVE ──firstTouch(赢家)──▶ ROTATING ──completeRotation──▶ ROTATED
  ▲                            │
  └──── rollbackToActive ──────┘            任意状态 ──markRevoked──▶ REVOKED
        （赢家在非轮换类失败时归还）
```

- `ACTIVE`：可正常轮换。
- `ROTATING`：某批次的赢家已领取、但尚未发布完成；并发同伴在此期间到达。
- `ROTATED`：本轮换新已完成；自完成时刻起进入**重叠窗口**（默认 2000ms，
  `auth.security.refresh-concurrent-overlap-millis`）。
- `REVOKED`：链路级终态（注销 / 重放 / 过期赢家失败）。

### 2.2 与调度无关的「首次触碰」分类（核心规则）

每次 `/refresh` 在做**任何阻塞之前**，先对所出示的刷新令牌执行**唯一一个原子的首次触碰**
（`RefreshTokenRecord.firstTouch`，方法本身 `synchronized`，检查与领取合为一步）：

| 首次触碰时观察到的状态 | 结论 | HTTP / 原因码 | 是否影响链路 |
|------------------------|------|----------------|--------------|
| `ACTIVE`（唯一赢家，原子翻成 `ROTATING`） | 执行且仅执行一次轮换，成功 | 200 | 正常推进 |
| `ROTATING`，或 `ROTATED` 且 `now - rotatedAt ≤ 重叠窗口` | **良性并发冲突** | **409 `refresh_concurrent_conflict`** | **不影响**，赢家新凭证照常可用 |
| `ROTATED` 且 `now - rotatedAt > 重叠窗口` | **真正的事后重放** | 401 `refresh_token_replay_sequential` | 整条链路判 `COMPROMISED` |
| `REVOKED` / 会话已终态 | 已终止链路上的使用 | 401 `chain_revoked_*` | 已终止 |

为什么这个结论与线程调度无关：良性 / 恶意的唯一判据是**令牌自身状态**与**轮换完成后的真实时间距离**，
不依赖「哪个线程先拿到锁」。于是：

- 一批请求无论怎么被操作系统调度、被调度得多晚，只要它的首次触碰仍在重叠窗口内，就永远是
  并发冲突；反复重跑同一批，结论恒为「1 次成功 + N 个相同的 409」。
- 慢线程不再被误判成「又一次独立重放」，良性客户端并发重试不会把整条会话连同赢家新凭证一起判死。
- 只有在这轮换新**彻底结束并越过重叠窗口之后**才出示旧凭证，才落在顺序重放结论上并让链路失效。

**适用边界（请务必知悉）**：重叠窗口是「在途/紧邻重试」与「事后重放」之间的时间切割。落在窗口内的
重复出示一律按良性并发处理——这是为了不伤害正常客户端的并发/迟到重试所做的明确取舍。因此该机制
防御的是「窗口之后的令牌被盗重放」；窗口应按客户端重试与服务端处理抖动的合理上界配置（默认 2000ms），
不宜过大。若赢家因非轮换原因失败（调用方不匹配、令牌恰好过期、凭证被回收），它会把令牌
`rollbackToActive()` 或置 `REVOKED` 并唤醒等待者，等待者按最新状态重新分类，不会被永久挂在
`ROTATING`；万一赢家在窗口内始终未发布，等待者得到独立的 409 `refresh_inflight_timeout`。

### 2.3 良性并发后链路仍可继续

赢家在 family 排他锁内原子地完成「发布 ROTATED + 签发新令牌对」。并发冲突只拒绝本次重复出示：

- 会话保持 `ACTIVE`；
- 赢家刚签发的新访问令牌可正常访问资源；
- 赢家的新刷新令牌可继续正常轮换。

### 2.4 真正重放的链路级后果（只针对窗口之后的重用）

一旦判定为 `refresh_token_replay_sequential`：会话置 `COMPROMISED`（终态、先到先得），
被盗链路上的后续刷新一律 `chain_revoked_replay`，family 内未过期访问令牌立即返回
`access_token_revoked_replay`；其它 family 完全不受影响。

---

## 3. 撤销与失效传播规则

| 触发动作 | 会话终态 | 未过期访问令牌 | 后续刷新 | 稳定原因码 |
|----------|----------|----------------|----------|------------|
| `/logout` | `LOGGED_OUT` | 立即不可用 | 一律拒绝 | `access_token_revoked_logout` / `chain_revoked_logout` |
| 窗口之后重放旧凭证 | `COMPROMISED` | 立即不可用 | 一律拒绝（含赢家新令牌） | `access_token_revoked_replay` / `chain_revoked_replay` |
| 窗口之内重复出示 | 不变（`ACTIVE`） | 正常 | 赢家新凭证正常 | 409 `refresh_concurrent_conflict`（不判死） |
| 重复注销已注销会话 | `LOGGED_OUT` | —— | —— | 幂等成功（日志 basis=`already_logged_out_idempotent`） |

访问令牌校验在每次请求时通过 **family 锁内一致性快照**同时读取令牌与其会话
（`TokenStore.snapshotAccessToken`），因此与轮换 / 注销 / 回收并发时，两个观测不可能互相矛盾，
也不存在「撤销黑名单延迟」。

---

## 4. 限流身份的信任边界

配额键**绝不直接取自客户端声明的 `X-Caller-Id`**。请求先由 `CallerIdentityGate` 解析「服务端认定的
身份」，再据此进入三层相互隔离的计费桶：

| 信任层 Tier | 适用请求 | 计费桶 | 伪造能否消耗真实额度 |
|-------------|----------|--------|----------------------|
| **TRUSTED** | 携带有效凭证；配额记到凭证的**服务端归属者** | 归属调用方自己的桶 | 不能：声明的头与归属不符时仍只记归属者 |
| **UNAUTHENTICATED** | 尚无凭证的入口：`/login`、`/maintenance/reclaim` | 保留命名空间的共享「未认证」桶 | 不能：与任何真实调用方桶隔离 |
| **UNTRUSTED** | 伪造 / 无效 / 缺失凭证（查无此令牌、无 Bearer、孤儿凭证） | 保留命名空间的共享「不可信」桶 | 不能：与任何真实调用方桶隔离 |

关键结论：

- **拿自己的有效令牌却把 `X-Caller-Id` 写成别人**：请求计费到令牌真正的归属者（攻击者自己）头上，
  头里写的受害者额度分毫不动；随后由鉴权返回 `access_token_caller_mismatch`。
- **拿无效 / 伪造凭证来刷**：进入不可信桶，返回各自既有的可区分安全码
  （`access_token_unknown` / `refresh_token_unknown` / `access_token_missing` 等），
  不触碰任何真实调用方窗口；不可信洪峰本身会被该共享桶的上限以 429 兜底。
- **登录入口伪造身份**：登录无凭证可认定，统一计入未认证桶，不可能占用或消耗任何真实调用方配额；
  完全缺失身份头仍返回 400 `caller_identity_missing`，且该拒绝不登记任何计数。
- 真实调用方之间继续互不影响；滑动窗口边界（`(now-window, now]`，等于窗口长度的旧请求被淘汰）
  与并发下的判定保持原有确定性，被拒请求不登记。

> 信任边界说明：登录时 `X-Caller-Id` 仍是「自报家门」，它决定新会话归属谁；本服务不做登录侧的
> 强身份认证（如 mTLS / 签名 / 网关下发身份）。一旦凭证签发，此后所有请求的配额归属都以服务端凭证
> 为准，头无法再伪造他人额度。若需要登录入口也不可伪造，应在更上游由可信网关注入身份。

---

## 5. 容量回收策略（`StateReclaimer`）

`POST /api/auth/maintenance/reclaim` 触发一次**同步、按需、可在并发流量进行中运行**的清理。

清理对象（只回收「永远彻底无用」的数据）：

- **终态会话**：`LOGGED_OUT` / `COMPROMISED`；
- **终态刷新令牌**：`REVOKED`，或其所属会话已终态；
- **终态访问令牌**：自身已撤销，或所属会话已终态；
- **自然过期的刷新 / 访问令牌**。

安全性：

- 每条删除决定都在该 family 的**排他锁内重新复核**后才执行，与轮换 / 注销 / 校验修改状态的位置
  完全一致，所以扫描与删除之间状态变化不会导致误删；正在有效期内的会话与凭证绝不删除。
- 过期判定与鉴权使用**同一个谓词** `expiresAt <= now`：恰好到边界的凭证在这里同样算过期，
  既不会被当成有效保留，也不会把未到期凭证提前清掉。
- 令牌先清、会话最后清；只有终态、或已不持有任何可用刷新凭证且不持有任何存活访问凭证的会话才删除，
  因此不会留下指向已删会话的孤儿令牌。

可观测结果 `ReclaimReport`（字段即「各类别扫描数 / 删除数」）：

```json
{
  "atMillis": 1700003601000,
  "sessionsScanned": 3,
  "terminalSessionsRemoved": 1,
  "refreshTokensScanned": 5,
  "terminalRefreshTokensRemoved": 1,
  "expiredRefreshTokensRemoved": 1,
  "accessTokensScanned": 6,
  "terminalAccessTokensRemoved": 2,
  "expiredAccessTokensRemoved": 1,
  "totalRemoved": 6
}
```

每次回收同时打印结构化日志 `decision=reclaim ...`，便于判断策略是否生效。兼容范围：回收仅删除
已死数据，存活链路行为不变；被回收的旧凭证若再次出示，按「服务端查无此令牌」返回
`*_token_unknown`（与从未存在一致，依旧是拒绝）。限流器自身另提供 `evictIdleState()`，只清理窗口内
已空、时间戳全部老化的键，不会删除仍可能影响判定的数据。

---

## 6. 稳定的判定原因码

| 原因码 | HTTP | 含义 |
|--------|------|------|
| `caller_identity_missing` | 400 | 缺少 `X-Caller-Id`（登录/入口直接拒，不登记计数） |
| `rate_limit_exceeded` | 429 | 所在信任桶（归属调用方 / 未认证 / 不可信）超出滑动窗口限额 |
| `access_token_missing` | 401 | 未携带 Bearer 令牌（计入不可信桶） |
| `access_token_unknown` | 401 | 服务端查无此令牌（计入不可信桶） |
| `access_token_caller_mismatch` | 401 | 出示者不是令牌归属调用方（配额仍记归属者） |
| `access_token_expired` | 401 | 访问令牌已过期 |
| `access_token_revoked_logout` | 401 | 会话注销导致的即时失效 |
| `access_token_revoked_replay` | 401 | 重放判定导致的链路级失效 |
| `refresh_token_unknown` | 401 | 服务端查无此刷新令牌（计入不可信桶） |
| `refresh_token_caller_mismatch` | 401 | 出示者不是该链路归属调用方 |
| `refresh_token_expired` | 401 | 刷新令牌已过期 |
| `refresh_concurrent_conflict` | **409** | 同一凭证在轮换在途 / 重叠窗口内被重复出示（良性，不杀链） |
| `refresh_inflight_timeout` | **409** | 赢家在重叠窗口内始终未发布完成 |
| `refresh_token_replay_sequential` | 401 | 越过重叠窗口后重用旧刷新令牌（真正重放，杀链） |
| `chain_revoked_logout` | 401 | 已注销链路上的刷新尝试 |
| `chain_revoked_replay` | 401 | 已判定重放的链路上的后续刷新 |

每个被拒绝的请求都打印结构化日志，包含**调用方标识、信任层、令牌状态、原因码与判定依据**，例如：

```
decision=refresh accepted=false callerId=app-1 familyId=f1a2 tokenState=ROTATED
  reason=refresh_concurrent_conflict basis=duplicate_presentation_overlaps_..._within_window_ms=2000
decision=rate_limit accepted=false tier=UNTRUSTED declaredCallerId=app-1 tokenState=UNKNOWN
  reason=access_token_unknown basis=identity_or_credential_not_server_attested real_caller_quota_charged=false
decision=reclaim accepted=true ... refresh(scanned=5,terminalRemoved=1,expiredRemoved=1) ...
```

---

## 7. 在本地复现 / 验证结论

时间相关结论（过期、窗口边界、重叠窗口前后）由测试中的 `MutableClock` 驱动，**确定性、可复现**，
不依赖 `sleep` 或真实线程时序。

```bash
mvn test
```

| 测试类 | 覆盖内容 |
|--------|----------|
| `AuthServiceTest` | 登录、原子轮换、顺序重放杀链、**16 线程并发恰好一次成功且其余全为同一 409、链路存活且赢家新凭证可继续访问/轮换**、**5 次复跑结论恒定**、窗口内/窗口后分类、注销传播、family 隔离、过期、调用方不匹配 |
| `CallerRateLimiterTest` | 限额边界、窗口边界（999ms 挡 / 1000ms 放）、调用方隔离、50 线程并发无漏放 |
| `CallerIdentityGateTest` | **伪造头只消耗令牌归属者额度、无效/伪造凭证不消耗真实额度、登录走未认证桶、缺失身份不计数、不可信洪峰被独立兜底** |
| `StateReclaimerTest` | **终态/过期清理、有效会话与兄弟会话不被误删、`expiresAt==now` 边界按过期回收、8 线程轮换与回收并发不删有效链路、回收报告可观测且二次扫为空** |
| `AuthHttpIntegrationTest` | 真实 HTTP：登录/访问/轮换、**12 线程并发一次 200 其余相同 409 且链路继续可用**、窗口后重放杀链、注销即时生效、缺身份 / 跨调用方 |
| `RateLimitHttpIntegrationTest` | 真实 HTTP 信任边界、伪造不消耗受害者额度、真实调用方隔离、未认证桶独立、窗口边界 |

关键断言一览（肉眼核对点）：

- 并发批：`success=1`，`conflict=N`，`other=0`；结束后会话 `ACTIVE`，赢家新 access 校验通过、
  新 refresh 可再轮换；多次复跑计数完全一致。
- 越过窗口（`MutableClock.advanceMillis(2001)`）后重用旧凭证：`refresh_token_replay_sequential`，
  会话 `COMPROMISED`，赢家新 access 立即 `access_token_revoked_replay`。
- 伪造/无效身份流量之后，受害者自己的前 5 个请求仍全部放行。
- 并发轮换 + 连续回收之后，有效会话仍在、新凭证仍可轮换并校验通过。

测试日志（控制台 `System.out` 摘要 + SLF4J 明细）保留调用方标识、凭证状态、信任层与判定依据，形如：

```
[concurrent-refresh] callerId=caller-C threads=16 success=1 conflict=15 other=0 otherReasons=[]
[concurrent-refresh-rerun] run=3 callerId=caller-C success=1 conflict=11 other=0
[trust-boundary] untrustedFlood=5xunknown+1x429 victimWindow=5/5-free
[reclaim-concurrent] familyId=... finalState=ACTIVE_and_rotatable failures=0
[http-rate-limit-trust] spoofedHeader=rl-victim(attackerToken)x4->caller_mismatch ... real_caller_spoofed_quota_charged=false
```

---

## 8. 配置项（`application.properties`）

```properties
auth.security.access-token-ttl-millis=300000      # 访问令牌 TTL
auth.security.refresh-token-ttl-millis=3600000    # 刷新令牌 TTL
auth.security.rate-limit-max-requests=5           # 每个信任桶每窗口最大请求数
auth.security.rate-limit-window-millis=1000       # 滑动窗口长度
auth.security.refresh-concurrent-overlap-millis=2000  # 良性并发重叠窗口：窗口内重复=409 不杀链，窗口后=重放杀链
```

## 9. 代码结构

```
domain/        Session、RefreshTokenRecord（ACTIVE/ROTATING/ROTATED/REVOKED + 首次触碰协议）、
               AccessTokenRecord、TokenPair、AccessVerification
store/         TokenStore 接口与 InMemoryTokenStore（family 锁、一致性快照、回收用删除/枚举原语）
ratelimit/     CallerRateLimiter（三层信任域滑动窗口）、CallerIdentityGate（服务端身份信任边界）、
               RateLimitDecision
service/       AuthService（首次触碰并发分类/轮换/重放/注销/锁内快照校验）、TokenFactory、
               AuthErrorCode、AuthException
maintenance/   StateReclaimer（安全回收）、ReclaimReport（分类别可观测结果）
web/           AuthController（在入口调用信任闸门）、ApiExceptionHandler、WebMvcConfig、RateLimitHeaders
config/        SecurityProperties
time/          Clock 抽象与 SystemClock（测试用 MutableClock 替换）
```
