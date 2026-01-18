package com.jaypal.authapp.domain.audit.entity;

public enum AuditSeverity {
    LOW,        // expected noise, invalid credentials
    MEDIUM,     // suspicious but common
    HIGH,       // security relevant
    CRITICAL    // compromise or system failure
}
