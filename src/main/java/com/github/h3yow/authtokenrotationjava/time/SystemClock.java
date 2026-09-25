package com.github.h3yow.authtokenrotationjava.time;

import org.springframework.stereotype.Component;

/** Default clock backed by the system wall clock. */
@Component
public class SystemClock implements Clock {
    @Override
    public long nowMillis() {
        return System.currentTimeMillis();
    }
}
