package com.github.h3yow.authtokenrotationjava.maintenance;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Optional background sweep. Activated only when
 * {@code auth.reclamation.schedule-enabled=true}; the fixed delay comes from
 * {@code auth.reclamation.sweep-interval-millis}. The manual
 * {@code POST /internal/maintenance/purge} endpoint is always available.
 */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(ReclamationProperties.class)
@ConditionalOnProperty(prefix = "auth.reclamation", name = "schedule-enabled", havingValue = "true")
public class ReclamationScheduler {

    private final StateReclamationService reclamationService;

    public ReclamationScheduler(StateReclamationService reclamationService) {
        this.reclamationService = reclamationService;
    }

    @Scheduled(fixedDelayString = "${auth.reclamation.sweep-interval-millis:60000}")
    public void scheduledSweep() {
        reclamationService.purgeNow();
    }
}
