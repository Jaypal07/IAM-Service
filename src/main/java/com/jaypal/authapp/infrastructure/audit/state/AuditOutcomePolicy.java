package com.jaypal.authapp.infrastructure.audit.state;

import com.jaypal.authapp.domain.audit.entity.AuditOutcome;

public interface AuditOutcomePolicy {
    AuditOutcome resolve(AuditSignal signal);
}
