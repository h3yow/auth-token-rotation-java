package com.github.h3yow.authtokenrotationjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * 令牌生命周期配置。
 */
@ConfigurationProperties(prefix = "auth.token")
public record AuthProperties(
        Duration accessTtl,
        Duration refreshTtl,
        Duration replayGraceWindow
) {
    public AuthProperties {
        if (accessTtl == null) accessTtl = Duration.ofSeconds(300);
        if (refreshTtl == null) refreshTtl = Duration.ofSeconds(1800);
        if (replayGraceWindow == null) replayGraceWindow = Duration.ofSeconds(2);
    }
}
