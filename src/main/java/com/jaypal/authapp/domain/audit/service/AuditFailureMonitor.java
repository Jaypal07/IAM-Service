package com.jaypal.authapp.domain.audit.service;

import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Component
public class AuditFailureMonitor {

    private static final long ALERT_THRESHOLD = 100L;
    private static final long CRITICAL_THRESHOLD = 1000L;

    private final AtomicLong failureCount = new AtomicLong(0);
    private final AtomicLong lastAlertCount = new AtomicLong(0);
    private volatile Instant lastAlert = Instant.now();

    public void onAuditFailure(AuthAuditEvent event, Exception ex) {
        final long count = failureCount.incrementAndGet();

        log.error("AUDIT_WRITE_FAILURE count={} event={}", count, event, ex);

        if (count % ALERT_THRESHOLD == 0) {
            log.error("ALERT: Audit failure count reached {} - audit logging is degraded!", count);
        }

        if (count >= CRITICAL_THRESHOLD) {
            log.error("CRITICAL: Audit failure count exceeded {} - audit logging is severely degraded!",
                    CRITICAL_THRESHOLD);
        }
    }

    public long getFailureCount() {
        return failureCount.get();
    }

    @Scheduled(fixedRate = 60000)
    public void reportStatus() {
        final long currentCount = failureCount.get();
        final long lastCount = lastAlertCount.get();

        if (currentCount > lastCount) {
            final long failuresSinceLastReport = currentCount - lastCount;
            log.warn("Audit failures in last minute: {} (total: {})",
                    failuresSinceLastReport, currentCount);
            lastAlertCount.set(currentCount);
            lastAlert = Instant.now();
        }
    }

    public boolean isHealthy() {
        return failureCount.get() < CRITICAL_THRESHOLD;
    }

    public Instant getLastAlert() {
        return lastAlert;
    }

    public void reset() {
        final long previousCount = failureCount.getAndSet(0);
        lastAlertCount.set(0);
        log.info("Audit failure monitor reset - previous count: {}", previousCount);
    }
}

/*
CHANGELOG:
1. Added threshold-based alerting (100, 1000 failures)
2. Added scheduled reporting (every minute)
3. Added health check method for monitoring
4. Added reset functionality for manual intervention
5. Made lastAlert volatile for thread visibility
6. Added tracking of failures since last report
7. Added isHealthy() for health endpoint integration
*/