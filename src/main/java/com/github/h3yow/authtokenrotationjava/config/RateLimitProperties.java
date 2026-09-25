package com.github.h3yow.authtokenrotationjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * 按调用方身份（clientId）维度的限流配置：滑动窗口内最多 maxRequests 次请求。
 */
@ConfigurationProperties(prefix = "auth.ratelimit")
public record RateLimitProperties(
        Integer maxRequests,
        Duration window
) {
    public RateLimitProperties {
        if (maxRequests == null) maxRequests = 10;
        if (window == null) window = Duration.ofSeconds(10);
    }
}
