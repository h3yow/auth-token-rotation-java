package com.github.h3yow.authtokenrotationjava.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC configuration.
 *
 * <p>Rate limiting is intentionally not a blind pre-controller interceptor any
 * more: the caller identity must be resolved <em>from the presented
 * credential</em> before any quota can be charged, so the trust-boundary probe
 * runs inside {@link AuthController} via {@code CallerIdentityGate}.
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
}
