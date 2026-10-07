package com.github.h3yow.authtokenrotationjava.maintenance;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Observable result of one reclamation sweep: how many entries of each
 * category were removed and at which logical instant.
 */
public record CleanupReport(long atMillis, long durationMillis,
                            Map<String, Integer> removedByCategory,
                            int familiesScanned, int totalRemoved) {

    public static Builder builder(long atMillis) {
        return new Builder(atMillis);
    }

    public static final class Builder {
        private final long atMillis;
        private long durationMillis;
        private int familiesScanned;
        private final Map<String, Integer> removed = new LinkedHashMap<>();

        private Builder(long atMillis) {
            this.atMillis = atMillis;
        }

        public Builder durationMillis(long durationMillis) {
            this.durationMillis = durationMillis;
            return this;
        }

        public Builder familiesScanned(int familiesScanned) {
            this.familiesScanned = familiesScanned;
            return this;
        }

        public Builder add(String category, int count) {
            removed.merge(category, count, Integer::sum);
            return this;
        }

        public CleanupReport build() {
            int total = removed.values().stream().mapToInt(Integer::intValue).sum();
            return new CleanupReport(atMillis, durationMillis,
                    java.util.Collections.unmodifiableMap(new LinkedHashMap<>(removed)),
                    familiesScanned, total);
        }
    }
}
