package com.jaypal.authapp.config.health;

import com.jaypal.authapp.domain.audit.service.AuditFailureMonitor;
import lombok.AllArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class AuditHealthIndicator implements HealthIndicator {
    private final AuditFailureMonitor monitor;

    @Override
    public Health health() {
        return monitor.isHealthy()
                ? Health.up()
                .withDetail("failures", monitor.getFailureCount())
                .build()
                : Health.down()
                .withDetail("failures", monitor.getFailureCount())
                .withDetail("lastAlert", monitor.getLastAlert())
                .build();
    }
}
