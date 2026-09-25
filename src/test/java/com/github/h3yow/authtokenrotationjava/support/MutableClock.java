package com.github.h3yow.authtokenrotationjava.support;

import com.github.h3yow.authtokenrotationjava.time.Clock;

import java.util.concurrent.atomic.AtomicLong;

/** Manually controllable clock for deterministic time-based tests. */
public class MutableClock implements Clock {

    private final AtomicLong now = new AtomicLong(1_700_000_000_000L);

    @Override
    public long nowMillis() {
        return now.get();
    }

    public void setMillis(long millis) {
        now.set(millis);
    }

    public void advanceMillis(long delta) {
        now.addAndGet(delta);
    }
}
