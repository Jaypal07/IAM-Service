package com.jaypal.authapp.infrastructure.audit.state;

public record AuditSignal(
        Object result,
        Throwable exception,
        boolean explicitNoOp,
        boolean explicitRejection
) {}
