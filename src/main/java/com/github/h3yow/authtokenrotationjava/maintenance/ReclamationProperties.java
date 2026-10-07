package com.github.h3yow.authtokenrotationjava.maintenance;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Tunable state-reclamation parameters, prefixed with
 * {@code auth.reclamation}.
 */
@ConfigurationProperties(prefix = "auth.reclamation")
public class ReclamationProperties {

    /** Whether the background sweep scheduler is enabled. */
    private boolean scheduleEnabled = false;

    /** Fixed delay between background sweeps in milliseconds. */
    private long sweepIntervalMillis = 60_000L;

    public boolean isScheduleEnabled() {
        return scheduleEnabled;
    }

    public void setScheduleEnabled(boolean scheduleEnabled) {
        this.scheduleEnabled = scheduleEnabled;
    }

    public long getSweepIntervalMillis() {
        return sweepIntervalMillis;
    }

    public void setSweepIntervalMillis(long sweepIntervalMillis) {
        this.sweepIntervalMillis = sweepIntervalMillis;
    }
}
