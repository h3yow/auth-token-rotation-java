package com.github.h3yow.authtokenrotationjava.domain;

/** Server-side state of a single refresh token in a rotation chain. */
public class RefreshTokenRecord {

    /** Lifecycle state of one refresh token. */
    public enum State {
        ACTIVE,
        /** The winning attempt of a concurrent batch has claimed the token but has not finished rotating yet. */
        ROTATING,
        ROTATED,
        REVOKED
    }

    /**
     * Result of an attempt's single atomic <em>first touch</em> on a refresh
     * token. This classification depends only on the token's own state and the
     * overlap window, never on thread scheduling, so re-running the same batch
     * always produces the same multiset of verdicts.
     */
    public enum FirstTouch {
        /** Caller won the one-shot claim; it must perform the rotation. */
        WINNER,
        /** Another attempt is/was in flight inside the overlap window: benign concurrent conflict. */
        CONCURRENT,
        /** The token was rotated and the overlap window has elapsed: a real post-hoc replay. */
        SEQUENTIAL_REPLAY,
        /** The whole chain was already terminated. */
        CHAIN_TERMINATED
    }

    private final String tokenId;
    private final String familyId;
    private final long issuedAtMillis;
    private final long expiresAtMillis;
    private volatile State state;
    private volatile long rotatedAtMillis;
    private volatile long rotatingSinceMillis;

    public RefreshTokenRecord(String tokenId, String familyId, long issuedAtMillis, long expiresAtMillis) {
        this.tokenId = tokenId;
        this.familyId = familyId;
        this.issuedAtMillis = issuedAtMillis;
        this.expiresAtMillis = expiresAtMillis;
        this.state = State.ACTIVE;
    }

    public String getTokenId() {
        return tokenId;
    }

    public String getFamilyId() {
        return familyId;
    }

    public long getIssuedAtMillis() {
        return issuedAtMillis;
    }

    public long getExpiresAtMillis() {
        return expiresAtMillis;
    }

    public State getState() {
        return state;
    }

    public long getRotatedAtMillis() {
        return rotatedAtMillis;
    }

    /**
     * The single atomic decision point at the very start of every refresh
     * attempt, before any blocking or locking:
     * <ul>
     *   <li>{@link State#ACTIVE}: this attempt is the unique winner; the token
     *       is claimed as {@link State#ROTATING}.</li>
     *   <li>{@link State#ROTATING}: a rotation is in flight right now, so this
     *       attempt is a member of the same concurrent batch.</li>
     *   <li>{@link State#ROTATED}: a rotation finished. If it finished within
     *       {@code overlapMillis} the late-but-overlapping attempt is still a
     *       benign concurrent conflict (it may simply have been scheduled
     *       late); otherwise it is a true post-hoc replay.</li>
     *   <li>{@link State#REVOKED}: the chain is already terminated.</li>
     * </ul>
     * Because the check and the ACTIVE&rarr;ROTATING claim are one
     * synchronized operation, the verdict multiset is independent of how the
     * contending threads are scheduled or how many times the batch is re-run.
     */
    public synchronized FirstTouch firstTouch(long now, long overlapMillis) {
        return switch (state) {
            case ACTIVE -> {
                state = State.ROTATING;
                rotatingSinceMillis = now;
                notifyAll();
                yield FirstTouch.WINNER;
            }
            case ROTATING -> FirstTouch.CONCURRENT;
            case ROTATED -> now - rotatedAtMillis <= overlapMillis
                    ? FirstTouch.CONCURRENT
                    : FirstTouch.SEQUENTIAL_REPLAY;
            case REVOKED -> FirstTouch.CHAIN_TERMINATED;
        };
    }

    /**
     * The winner gives the claim back after a non-rotation failure (caller
     * mismatch, expiry), so a legitimate later attempt on the still-valid token
     * can proceed. Waiting contenders are woken to re-classify.
     */
    public synchronized void rollbackToActive() {
        if (state == State.ROTATING) {
            state = State.ACTIVE;
            rotatingSinceMillis = 0L;
            notifyAll();
        }
    }

    /** The winner publishes the finished rotation; the overlap window starts now. */
    public synchronized void completeRotation(long atMillis) {
        if (state == State.ROTATING) {
            state = State.ROTATED;
            rotatedAtMillis = atMillis;
            rotatingSinceMillis = 0L;
            notifyAll();
        }
    }

    /**
     * Block a concurrent contender until the winner finishes or rolls back, or
     * until {@code timeoutMillis} elapse. Returns {@code true} once the token
     * has left {@link State#ROTATING}.
     */
    public synchronized boolean awaitResolution(long timeoutMillis) throws InterruptedException {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        long remaining = timeoutMillis;
        while (state == State.ROTATING && remaining > 0L) {
            wait(remaining);
            remaining = Math.max(0L, java.util.concurrent.TimeUnit.NANOSECONDS
                    .toMillis(deadline - System.nanoTime()));
        }
        return state != State.ROTATING;
    }

    /** Terminal revocation (chain logout or replay detection). */
    public synchronized void markRevoked() {
        if (state != State.REVOKED) {
            state = State.REVOKED;
        }
        notifyAll();
    }
}
