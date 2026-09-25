package com.github.h3yow.authtokenrotationjava.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * 测试用可拨动时钟：令牌过期与限流时间窗边界都基于它判定，保证测试确定可复现。
 */
public class MutableClock extends Clock {

    private Instant current;
    private final ZoneId zone;

    public MutableClock(Instant initial) {
        this.current = initial;
        this.zone = ZoneOffset.UTC;
    }

    public void advance(Duration duration) {
        this.current = current.plus(duration);
    }

    public void setInstant(Instant instant) {
        this.current = instant;
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Instant instant() {
        return current;
    }
}
