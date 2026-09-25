package com.github.h3yow.authtokenrotationjava.domain;

import java.time.Instant;

/**
 * 一次刷新操作在 family 锁段内得出的原子结论。
 *
 * <p>只有 {@link Rotated} 表示成功并携带新令牌对；其余结论均为可区分的拒绝原因，
 * 其中 {@link ReplayDetected} 表示已在锁内完成整条链路撤销。</p>
 */
public sealed interface RotationOutcome {

    record Rotated(TokenPair tokenPair, String oldTokenId) implements RotationOutcome {
    }

    /** 宽限窗口内再次出现：并发竞争落败，链路保持有效（不影响合法会话）。 */
    record ConcurrentRace(String reusedTokenId, Instant lastRotationAt) implements RotationOutcome {
    }

    /** 宽限窗口外再次出现：判定为重放，整条链路已在锁内撤销。 */
    record ReplayDetected(String reusedTokenId) implements RotationOutcome {
    }

    enum Rejection implements RotationOutcome {
        UNKNOWN,
        FAMILY_REVOKED,
        REFRESH_EXPIRED
    }
}
