package com.github.h3yow.authtokenrotationjava.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.time.Instant;

/**
 * 用固定起点的可拨动时钟替换系统时钟，使过期/限流窗口测试确定可复现。
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestClockConfiguration {

    public static final Instant FIXED_NOW = Instant.parse("2026-09-26T00:00:00Z");

    @Bean
    @Primary
    public MutableClock testClock() {
        return new MutableClock(FIXED_NOW);
    }
}
