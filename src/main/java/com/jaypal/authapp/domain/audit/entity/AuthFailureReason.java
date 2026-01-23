package com.jaypal.authapp.domain.audit.entity;

public enum AuthFailureReason {

    /* AUTH */
    INVALID_CREDENTIALS(AuditSeverity.LOW),
    USER_NOT_FOUND(AuditSeverity.LOW),
    ACCOUNT_DISABLED(AuditSeverity.HIGH),
    ACCOUNT_LOCKED(AuditSeverity.HIGH),

    /* OAUTH */
    OAUTH_PROVIDER_ERROR(AuditSeverity.MEDIUM),
    OAUTH_ACCOUNT_NOT_LINKED(AuditSeverity.MEDIUM),

    /* EMAIL */
    EMAIL_ALREADY_EXISTS(AuditSeverity.LOW),
    EMAIL_ALREADY_VERIFIED(AuditSeverity.LOW),
    EMAIL_NOT_VERIFIED(AuditSeverity.LOW),
    EMAIL_NOT_REGISTERED(AuditSeverity.LOW),
    EMAIL_VERIFICATION_TOKEN_INVALID(AuditSeverity.HIGH),
    EMAIL_VERIFICATION_TOKEN_EXPIRED(AuditSeverity.MEDIUM),

    /* TOKEN */
    TOKEN_MISSING(AuditSeverity.MEDIUM),
    TOKEN_INVALID(AuditSeverity.HIGH),
    TOKEN_EXPIRED(AuditSeverity.MEDIUM),
    TOKEN_REVOKED(AuditSeverity.CRITICAL),
    TOKEN_REFRESH_REUSED(AuditSeverity.CRITICAL),

    /* PASSWORD */
    PASSWORD_POLICY_VIOLATION(AuditSeverity.MEDIUM),
    PASSWORD_RESET_TOKEN_INVALID(AuditSeverity.HIGH),
    PASSWORD_RESET_TOKEN_EXPIRED(AuditSeverity.MEDIUM),
    PASSWORD_RESET_TOKEN_USED(AuditSeverity.HIGH),

    /* AUTHZ */
    ACCESS_DENIED(AuditSeverity.MEDIUM),
    INSUFFICIENT_ROLE(AuditSeverity.MEDIUM),
    INSUFFICIENT_PERMISSION(AuditSeverity.MEDIUM),

    /* ADMIN */
    ADMIN_TARGET_NOT_FOUND(AuditSeverity.LOW),
    ADMIN_OPERATION_FORBIDDEN(AuditSeverity.HIGH),

    /* RATE LIMIT */
    RATE_LIMIT_EXCEEDED(AuditSeverity.MEDIUM),
    BRUTE_FORCE_DETECTED(AuditSeverity.HIGH),

    /* SYSTEM */
    VALIDATION_FAILED(AuditSeverity.LOW),
    DEPENDENCY_FAILURE(AuditSeverity.CRITICAL),
    DATA_INTEGRITY_VIOLATION(AuditSeverity.CRITICAL),
    SYSTEM_ERROR(AuditSeverity.CRITICAL);

    private final AuditSeverity severity;

    AuthFailureReason(AuditSeverity severity) {
        this.severity = severity;
    }

    public AuditSeverity getSeverity() {
        return severity;
    }
}
