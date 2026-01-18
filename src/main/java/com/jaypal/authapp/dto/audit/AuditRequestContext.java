package com.jaypal.authapp.dto.audit;

public record AuditRequestContext(
        String ipAddress,
        String userAgent,
        String userId // nullable
) {}
