package com.jaypal.authapp.domain.audit.entity;

import com.jaypal.authapp.domain.dto.audit.AuditRequestContext;
import com.jaypal.authapp.audit.domain.*;
import jakarta.persistence.*;
import lombok.ToString;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@ToString
@Entity
@Table(
        name = "auth_audit_logs",
        indexes = {
                @Index(name = "idx_audit_created_at", columnList = "created_at"),
                @Index(name = "idx_audit_event", columnList = "event"),
                @Index(name = "idx_audit_subject_type", columnList = "subject_type"),
                @Index(name = "idx_audit_outcome", columnList = "outcome")
        }
)
public class AuthAuditLog {

    @Id
    @GeneratedValue()
    @UuidGenerator(style = UuidGenerator.Style.TIME)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false)
    private AuditCategory category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false)
    private AuthAuditEvent event;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false)
    private AuditOutcome outcome;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false)
    private AuditSeverity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "subject_type", nullable = false, updatable = false)
    private AuditSubjectType subjectType;

    @Column(name = "subject_identifier", updatable = false)
    private String subjectIdentifier;

    @Enumerated(EnumType.STRING)
    @Column(name = "failure_reason", updatable = false)
    private AuthFailureReason failureReason;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false)
    private AuthProvider provider;

    @Column(updatable = false)
    private String ipAddress;

    @Column(updatable = false)
    private String userAgent;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    protected AuthAuditLog() {}

    public AuthAuditLog(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditSeverity severity,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider,
            AuditRequestContext context
    ) {
        this.category = category;
        this.event = event;
        this.outcome = outcome;
        this.severity = severity;
        this.subjectType = subject.getType();
        this.subjectIdentifier = subject.getIdentifier();
        this.failureReason = failureReason;
        this.provider = provider;
        this.ipAddress = context != null ? context.ipAddress() : null;
        this.userAgent = context != null ? context.userAgent() : null;
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }
}
