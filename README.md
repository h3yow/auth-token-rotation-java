# Auth Token Rotation（访问令牌签发 / 轮换 / 并发判定 / 可信身份限流 / 状态回收）

一个基于 Spring Boot 3 / Java 21 的内存态令牌服务，目标是让鉴权结论在**并发刷新、令牌重放、
身份伪造与长期运行**四种情形下都保持**稳定、可解释、可复现**。

服务端保存每个令牌的状态（不使用无状态 JWT），因此撤销、重放判定与身份认定都**立即生效**，
不依赖令牌提前过期。

---

## 1. HTTP 接口

鉴权接口都携带调用方标识请求头 `X-Caller-Id`；但**限流是否计入某个调用方，以服务端凭证
认定为准，不再以该请求头为准**（见第 4 节）。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 签发会话与第一对令牌，请求体 `{"subject":"alice"}`（无凭证入口，见 4.3） |
| POST | `/api/auth/refresh` | 原子轮换，请求体 `{"refreshToken":"rtk_..."}`，旧刷新令牌立即失效并返回新令牌对 |
| POST | `/api/auth/logout` | 会话级注销，整条刷新链路与所有访问令牌立即失效 |
| POST | `/api/auth/resource` | 受保护资源，需 `Authorization: Bearer atk_...` |
| POST | `/internal/maintenance/purge` | 手动触发一次状态回收，返回分类清理计数（不在 `/api/**` 下，不消耗任何限流额度） |

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

回收响应（purge）：

```json
{
  "atMillis": 1700003600000,
  "durationMillis": 1,
  "removedByCategory": {
    "session_terminal": 1,
    "session_all_tokens_expired": 0,
    "refresh_token_records": 1,
    "access_token_records": 1,
    "orphan_refresh_token_records": 0,
    "orphan_access_token_records": 0,
    "idle_rate_limit_keys": 0
  },
  "familiesScanned": 1,
  "totalRemoved": 3
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

# 4) 轮换彻底结束并过了宽限窗之后，再用旧 RTK -> 401 refresh_token_replay_sequential，整条链路被杀
curl -s -i -X POST $BASE/api/auth/refresh -H 'X-Caller-Id: app-1' -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$OLD_RTK\"}"

# 5) 伪造身份：拿着别人的令牌却声明自己是另一个调用方 -> 401 caller_identity_untrusted，
#    不消耗令牌真实归属方的任何额度
curl -s -i -X POST $BASE/api/auth/resource -H 'X-Caller-Id: attacker' -H "Authorization: Bearer $ATK"

# 6) 手动回收
curl -s -X POST $BASE/internal/maintenance/purge
```

---

## 2. 令牌生命周期

一次登录产生一个 **Session（会话）**，会话拥有一个 `familyId`。该次登录以及之后每次轮换
得到的所有刷新/访问令牌都属于同一个 **family（刷新链路）**。

### 2.1 访问令牌（access token）

- 不透明高熵随机串（`atk_` + 256 bit，URL-safe Base64）。
- 默认 TTL **5 分钟**（`auth.security.access-token-ttl-millis`）。
- 访问时实时查询服务端记录与所属会话，撤销即时生效。

### 2.2 刷新令牌（refresh token）与轮换

- 不透明高熵随机串（`rtk_` + 256 bit）。
- 默认 TTL **60 分钟**（`auth.security.refresh-token-ttl-millis`）。
- 生命周期状态机：`ACTIVE -> ROTATED`（正常轮换）或任意状态 -> `REVOKED`（链路级失效）。
- 每次成功轮换时，被消耗的旧令牌会**持久记录它的后继刷新令牌（successor）**。
- 同一 family 的所有轮换在该 family 的排他锁内串行完成：状态翻转与新令牌签发作为一个整体
  对外可见，恰好一次成功。

### 2.3 并发判定：与线程调度无关的稳定结论（本次重点）

判定依据是**持久状态 + 逻辑时钟**，而不是“某个线程跑得快还是慢”：

1. 一张刷新令牌被赢家消耗后记录 `rotatedAt` 与后继令牌。
2. 该令牌被再次出示时：
   - 若距轮换不超过**良性并发宽限窗**（默认 30s，
     `auth.security.refresh-concurrent-grace-millis`，边界为闭区间 `age <= grace`），**且**
     后继刷新令牌仍是 `ACTIVE`，则归类为良性 **并发冲突**：
     HTTP **409** `refresh_conflict_concurrent`。**不杀链路**，会话保持 `ACTIVE`，
     赢家刚拿到的新访问令牌继续可用、新刷新令牌还能继续刷新。
   - 若宽限窗已过，**或**后继令牌本身也已被消耗（说明这一轮换新早已彻底结束），则归类为
     **事后顺序重放**：HTTP 401 `refresh_token_replay_sequential`，整条链路失效。

适用边界：

- 一批并发/重试请求，无论线程如何调度、应用层把这批请求复跑多少次：**永远恰好一次成功，
  其余全部得到同一个 `refresh_conflict_concurrent`**，结论恒定。
- 一张**早就被消耗**的旧凭证，是在这轮换新**彻底结束之后**（宽限窗已过，或后继已被继续
  轮换）才被拿出来用的，仍与并发情形明确区分，按既有规则让链路失效。
- 宽限窗只解决“良性并发重试”与“真正事后重放”的区分；它不是安全豁免——只要换新轮次已经
  结束（后继被继续使用），即使时间没走动也照样判重放。

### 2.4 重放的链路级后果（只针对真正的重放）

一旦判定为事后顺序重放：

1. 整个 Session 置为 `COMPROMISED`（终态，先到先得，不被后续注销覆盖）；
2. 链路上所有后续刷新一律返回 `chain_revoked_replay`（含赢家新令牌）；
3. 该 family 内所有尚未过期的访问令牌立即返回 `access_token_revoked_replay`；
4. **其它 family（其它会话 / 其它调用方）完全不受影响。**

> 良性并发冲突（409）**不触发**上述任何后果。

---

## 3. 撤销与失效传播规则

| 触发动作 | 会话终态 | 未过期访问令牌 | 后续刷新 | 稳定原因码 |
|----------|----------|----------------|----------|------------|
| `/logout` | `LOGGED_OUT` | 立即不可用 | 一律拒绝 | `access_token_revoked_logout` / `chain_revoked_logout` |
| 事后顺序重放 | `COMPROMISED` | 立即不可用 | 一律拒绝 | `access_token_revoked_replay` / `chain_revoked_replay` |
| 良性并发冲突 | 保持 `ACTIVE` | 赢家令牌继续可用 | 赢家令牌可继续刷新 | `refresh_conflict_concurrent`（409，非撤销） |
| 重复注销已注销会话 | `LOGGED_OUT` | —— | —— | 幂等成功（basis=`already_logged_out_idempotent`） |

访问令牌校验在**每次请求**时读取所属 Session 状态，注销/重放判定立即生效。终态首次写入优先：
`ACTIVE -> LOGGED_OUT / COMPROMISED` 单向迁移，判定依据不被后续动作掩盖。

---

## 4. 调用方限流：身份信任边界（本次重点）

- 算法仍是按 key 的**滑动窗口日志**（默认每 key **5 次 / 1000ms**，窗口 `(now-window, now]`，
  年龄等于窗长的旧请求被淘汰，边界确定性保持不变）。
- 关键变化：**计数维度不再是请求自己声明的 `X-Caller-Id`**。请求先过身份认定，只有被服务端
  凭证确认归属的请求才计入该真实调用方的配额。

### 4.1 身份如何被证明

- **带凭证接口**（refresh / logout / resource）：拦截器读取请求出示的访问/刷新令牌，在服务端
  存储中查证其真实归属调用方。
  - 声明头 == 凭证归属方 → 身份可信，计入该归属方的 **AUTHENTICATED** 桶，再继续业务判定。
  - 声明头 != 凭证归属方（**伪造**）、凭证服务端查无此证（**无效**）、或根本没带凭证 →
    HTTP 401 `caller_identity_untrusted`，**不计入任何真实调用方的配额**（连伪造者自己也不会
    被记到受害者名下）。
  - 凭证过期/被撤销不改变其归属：过期凭证仍能证明身份（照常计费），具体的过期/撤销结论由
    下游业务用既有原因码给出，结论仍可区分。
- **限流先于业务**：伪造/无效请求在计费之前就被挡下，无法用伪造身份刷爆别人，也无法继续
  探测令牌逻辑。

### 4.2 伪造的防护结论

| 情形 | 结论 | 是否消耗真实调用方额度 |
|------|------|------------------------|
| 拿 A 的令牌却声明自己是 B | 401 `caller_identity_untrusted` | 否（A、B 都不消耗） |
| 拿一个服务端不存在的令牌反复刷 | 401 `caller_identity_untrusted` | 否 |
| 不带任何凭证 | 401 `caller_identity_untrusted` | 否 |
| 缺少 `X-Caller-Id` 头 | 400 `caller_identity_missing` | 否 |

### 4.3 无凭证的签发入口（login）

login 时调用方还没有任何凭证，无法证明身份，因此它被计入一个**独立的 ISSUANCE 命名空间**，
按请求头原始值分桶。该桶与任何真实调用方的 AUTHENTICATED 桶物理隔离——在 login 上伪造身份
**不可能**占用或消耗任何真实调用方的已认证配额。

> 信任边界说明：ISSUANCE 桶只按自报身份隔离，因此攻击者仍可在 issuance 命名空间内对某个名字
> 发起洪水（这属于匿名签发面的 DoS，需在更外层用网络策略/签发凭证/验证码防护）；系统保证的
> 是它**绝不波及任何已认证真实调用方**。

### 4.4 隔离与边界保持不变

- 不同真实调用方（AUTHENTICATED 桶）之间互不影响；AUTHENTICATED 与 ISSUANCE 之间也互不影响。
- 窗口边界语义、并发下“不漏放”的原子计数与上一版完全一致。

---

## 5. 状态回收：可控、可观测、并发安全（本次重点）

长期运行后，会话注销、链路被判重放、凭证自然过期所产生的数据不会永久堆积。

### 5.1 回收内容与判定

回收由 `StateReclamationService` 执行，每次扫描在对应 family 的**排他锁内二次确认**后才删除，
因此可以在有并发访问进行时安全触发：

| 类别（removedByCategory key） | 回收条件 |
|-------------------------------|----------|
| `session_terminal` | 会话已处于终态 `LOGGED_OUT` / `COMPROMISED`（连同其全部令牌整体删除） |
| `session_all_tokens_expired` | ACTIVE 会话，但其**所有**刷新令牌与访问令牌都已自然过期 |
| `refresh_token_records` / `access_token_records` | 随上述 family 整体删除的令牌计数 |
| `orphan_refresh_token_records` / `orphan_access_token_records` | 所属会话已不存在、且自身也已过期的游离令牌 |
| `idle_rate_limit_keys` | 窗口已清空的空闲调用方限流桶（连同其锁对象） |

### 5.2 安全边界（不误删 / 边界口径一致）

- 只要 family 内还存在**任一**未过期凭证，该 family 一律保留（哪怕另一个凭证已过期）。
- “刚好到期”口径与全系统一致：`expiresAt <= now` 即失效。恰好在回收瞬间到期的凭证被当作
  **已失效**并可回收；到期前 1ms 仍保留。单测固定了 -1ms 保留 / 到期点回收这两个结论。
- 终态 family 的删除（会话 + 令牌 + family 锁）在持锁状态下完成，正在进行的访问/轮换不会
  读到“半删除”状态。
- 多个回收调用并发触发时不会重叠执行：已有 sweep 在跑则本次跳过（返回 null）。

### 5.3 触发方式与可观测结果

- 手动：`POST /internal/maintenance/purge`（始终可用）。
- 定时（默认关闭）：`auth.reclamation.schedule-enabled=true`，间隔
  `auth.reclamation.sweep-interval-millis`。
- 每次回收返回并打印：扫描 family 数、各类别清理数量、合计清理数、耗时与发生时刻，便于判断
  回收策略是否真的生效。

---

## 6. 稳定的判定原因码

| 原因码 | HTTP | 含义 |
|--------|------|------|
| `caller_identity_missing` | 400 | 缺少 `X-Caller-Id` |
| `caller_identity_untrusted` | 401 | 伪造/无效/缺失凭证，身份未被服务端证实（不计费） |
| `rate_limit_exceeded` | 429 | 被证实身份超出其滑动窗口限额 |
| `access_token_missing` | 401 | 未携带 Bearer 令牌 |
| `access_token_unknown` | 401 | 服务端查无此令牌 |
| `access_token_caller_mismatch` | 401 | 出示者不是令牌归属调用方 |
| `access_token_expired` | 401 | 访问令牌已过期 |
| `access_token_revoked_logout` | 401 | 会话注销导致的即时失效 |
| `access_token_revoked_replay` | 401 | 重放判定导致的链路级失效 |
| `refresh_token_unknown` | 401 | 服务端查无此刷新令牌 |
| `refresh_token_caller_mismatch` | 401 | 出示者不是该链路归属调用方 |
| `refresh_token_expired` | 401 | 刷新令牌已过期 |
| `refresh_conflict_concurrent` | **409** | 良性并发冲突：宽限窗内后继仍 ACTIVE，**不杀链路** |
| `refresh_token_replay_sequential` | 401 | 换新轮次彻底结束（宽限已过/后继已消耗）后重用旧令牌 |
| `chain_revoked_logout` | 401 | 已注销链路上的刷新尝试 |
| `chain_revoked_replay` | 401 | 已判定重放的链路上的后续刷新 |

> 说明：上一版的 `refresh_token_replay_concurrent`（401，会杀链路）已被新的
> `refresh_conflict_concurrent`（409，不杀链路）取代。二者语义不同：前者把良性并发误判成
> 攻击；后者明确表达“同批并发重试落败”，与真正重放区分开。

每个被拒绝请求都打印结构化日志，包含**调用方标识、令牌状态、原因码与判定依据**，例如：

```
decision=refresh accepted=false callerId=app-1 familyId=f1a2 tokenState=ROTATED
  reason=refresh_conflict_concurrent basis=token_already_ROTATED rotatedAt=1700000000000 now=1700000000000 graceMs=30000 withinGrace=true successorState=ACTIVE
decision=rate_limit accepted=false callerId=attacker tokenState=- reason=caller_identity_untrusted
  basis=declared_caller_differs_from_credential_owner_owner=app-1 tokenState=RECORDED path=/api/auth/resource
decision=reclamation accepted=true basis=sweep_completed familiesScanned=3 totalRemoved=5 removedByCategory={session_terminal=2, ...}
```

---

## 7. 验证方法（测试）

时间相关结论（过期、宽限窗、限流窗口、回收边界）由测试中的 `MutableClock` 驱动，
**确定性、可复现**，不依赖 `sleep` 或真实时钟。

```bash
mvn test
```

| 测试类 | 覆盖内容 |
|--------|----------|
| `AuthServiceTest` | 登录/轮换/注销/过期/调用方隔离；**良性并发恰好一次成功、其余同一 409、链路存活、赢家新凭证继续可用**；**并发批次复跑 3 轮结论恒定**；宽限边界（==grace 放行冲突 / +1ms 判重放）；后继已被消耗即使时间不走也判重放；事后重放整链失效 |
| `CallerIdentityResolverTest` | 有效凭证证明归属、**伪造头不可信且无计费桶**、未知/缺失凭证不可信、过期凭证仍证明身份、login 独立 ISSUANCE 命名空间 |
| `CallerRateLimiterTest` | 限额边界、窗口边界（999ms 挡 / 1000ms 放）、调用方隔离、50 线程并发只放行 5 个 |
| `StateReclamationServiceTest` | 终态/自然过期回收、部分过期保留、**到期边界（-1ms 保留 / 到期点回收）**、**回收与轮换/访问并发进行时不误删有效 family**、空闲限流桶回收 |
| `IdentityTrustHttpIntegrationTest` | 真实 HTTP：**伪造访问/刷新、未知令牌、无凭证洪水不消耗真实调用方额度（受害者仍满额 5 次）**、ISSUANCE 与 AUTHENTICATED 同刻互不影响 |
| `AuthHttpIntegrationTest` | 真实 HTTP 全链路；**12 线程并发刷新恰好 1×200 + 11×409 且赢家继续可用**；事后重放杀链；缺调用方 / 伪造身份 |
| `ReclamationHttpIntegrationTest` | 真实 HTTP 触发 purge 并返回分类计数 |
| `RateLimitHttpIntegrationTest` | 真实 HTTP 限流边界与跨调用方隔离 |

控制台还会打印便于肉眼核对的摘要，形如：

```
[concurrent-refresh] callerId=caller-C threads=16 success=1 conflict=15 other=0 otherReasons=[]
[concurrent-refresh-rerun] callerId=caller-R run=3 threads=12 success=0 conflict=12 other=0 sessionStatus=ACTIVE
[identity-quota] forged access x12 -> owner victim still allowed=5 blocked6th=429
[reclamation-concurrency] families=20 sweepsRun=.. rotationFailures=0
[http-reclamation] totalRemoved=3 categories={session_terminal=1, refresh_token_records=1, access_token_records=1, ...}
```

---

## 8. 配置项

```properties
auth.security.access-token-ttl-millis=300000        # 访问令牌 TTL
auth.security.refresh-token-ttl-millis=3600000      # 刷新令牌 TTL
auth.security.rate-limit-max-requests=5             # 每（被证实）身份每窗口最大请求数
auth.security.rate-limit-window-millis=1000         # 滑动窗口长度
auth.security.refresh-concurrent-grace-millis=30000 # 良性并发宽限窗（闭区间）
auth.reclamation.schedule-enabled=false             # 是否开启后台定时回收
auth.reclamation.sweep-interval-millis=60000        # 后台回收间隔
```

## 9. 代码结构

```
domain/        Session、RefreshTokenRecord（含 successor 指针）、AccessTokenRecord、TokenPair、AccessVerification
store/         TokenStore 接口与 InMemoryTokenStore（family 锁、遍历/删除/整 family 回收）
ratelimit/     RateLimitScope / RateLimitKey、CallerRateLimiter（双命名空间滑动窗口+空闲桶回收）、RateLimitDecision
identity/      CallerIdentity、CallerIdentityResolver（服务端凭证身份认定）
service/       AuthService（登录/轮换/并发冲突 vs 重放判定/注销/校验）、TokenFactory、AuthErrorCode、AuthException
maintenance/   StateReclamationService、CleanupReport、ReclamationProperties、ReclamationScheduler、MaintenanceController
web/           AuthController、RateLimitInterceptor、CachedBodyFilter/Request、ApiExceptionHandler、WebMvcConfig
config/        SecurityProperties
time/          Clock 抽象与 SystemClock（测试用 MutableClock 替换）
```

### 本地手动复现并发/身份/回收结论

```bash
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080
# 并发刷新：用同一张 RTK 并发发起多个 /api/auth/refresh
#   -> 恰好 1 个 200，其余 409 refresh_conflict_concurrent，会话仍 ACTIVE
# 事后重放：等待 30s 宽限过后（或先继续用新 RTK 轮换一次）再用旧 RTK
#   -> 401 refresh_token_replay_sequential，链路 COMPROMISED
# 伪造身份：拿到 A 的令牌后用 X-Caller-Id: B 访问 -> 401 caller_identity_untrusted，
#   再立刻用 A 的真实身份连续访问，额度未被伪造流量消耗
# 回收：制造 logout / 过期状态后 POST /internal/maintenance/purge，查看分类计数
```
