package com.jaypal.authapp.domain.dto.audit;

public record AuditRequestContext(
        String ipAddress,
        String userAgent,
        String userId // nullable
) {}
