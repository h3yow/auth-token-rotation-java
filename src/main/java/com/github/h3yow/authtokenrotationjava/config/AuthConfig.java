package com.github.h3yow.authtokenrotationjava.config;

import com.github.h3yow.authtokenrotationjava.service.ClientRateLimiter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 鉴权模块装配：统一时钟（测试可替换）、限流器与配置属性。
 */
@Configuration
@EnableConfigurationProperties({AuthProperties.class, RateLimitProperties.class})
public class AuthConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    public ClientRateLimiter clientRateLimiter(Clock clock, RateLimitProperties rateLimitProperties) {
        return new ClientRateLimiter(clock, rateLimitProperties.maxRequests(), rateLimitProperties.window());
    }
}
