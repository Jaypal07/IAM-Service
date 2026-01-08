package com.jaypal.authapp.audit.persistence;

import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuthFailureReason;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "auth_audit_logs",
        indexes = {
                @Index(name = "idx_audit_user_id", columnList = "userId"),
                @Index(name = "idx_audit_subject", columnList = "subject"),
                @Index(name = "idx_audit_event", columnList = "eventType"),
                @Index(name = "idx_audit_reason", columnList = "failureReason"),
                @Index(name = "idx_audit_created_at", columnList = "createdAt")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private UUID userId;

    private String subject;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthAuditEvent eventType;

    private String provider;

    @Column(nullable = false)
    private boolean success;

    @Enumerated(EnumType.STRING)
    private AuthFailureReason failureReason;

    private String ipAddress;

    private String userAgent;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
    }
}
