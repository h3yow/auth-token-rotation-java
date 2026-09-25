package com.github.h3yow.authtokenrotationjava.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Enables typed configuration properties. */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class AppConfig {
}
