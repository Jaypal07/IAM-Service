package com.jaypal.authapp.domain.audit.service;

import com.jaypal.authapp.dto.audit.AuditRequestContext;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.repository.AuthAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthAuditService {

    private final AuthAuditRepository repository;
    private final AuditFailureMonitor failureMonitor;

    /* ============================================================
       PUBLIC API
       ============================================================ */

    /**
     * Records an audit log asynchronously. Supports SUCCESS, FAILURE, and NO_OP outcomes.
     */
    @Async("auditExecutor")
    public void record(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider,
            AuditRequestContext context
    ) {
        final String thread = Thread.currentThread().getName();

        if (log.isDebugEnabled()) {
            log.debug(
                    "AUDIT invoked | thread={} category={} event={} outcome={} subject={} failureReason={} provider={}",
                    thread,
                    category,
                    event,
                    outcome,
                    subject,
                    failureReason,
                    provider
            );
        }

        try {
            // Validate invariants (NO_OP allowed)
            enforceInvariants(category, event, outcome, subject, failureReason, provider);

            // Determine severity
            AuditSeverity severity = determineSeverity(outcome, failureReason);

            AuthAuditLog auditLog = new AuthAuditLog(
                    category,
                    event,
                    outcome,
                    severity,
                    subject,
                    failureReason,
                    provider,
                    context
            );

            AuthAuditLog saved = repository.save(auditLog);

            switch (outcome) {
                case SUCCESS, NO_OP -> log.info(
                        "AUDIT persisted | auditId={} event={} outcome={} severity={}",
                        saved.getId(), event, outcome, severity
                );
                case FAILURE -> {
                    log.info(
                            "AUDIT persisted | auditId={} event={} outcome={} severity={}",
                            saved.getId(), event, outcome, severity
                    );
                    if (severity == AuditSeverity.CRITICAL) {
                        log.warn(
                                "AUDIT CRITICAL | event={} subject={} failureReason={} provider={}",
                                event, subject, failureReason, provider
                        );
                    }
                }
            }

        } catch (Exception ex) {
            log.error(
                    "AUDIT FAILED | event={} outcome={} subject={} provider={}",
                    event, outcome, subject, provider, ex
            );
            failureMonitor.onAuditFailure(event, ex);
        }
    }

    /* ============================================================
       INVARIANTS
       ============================================================ */

    private void enforceInvariants(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider
    ) {
        Objects.requireNonNull(category, "Audit category must not be null");
        Objects.requireNonNull(event, "Audit event must not be null");
        Objects.requireNonNull(outcome, "Audit outcome must not be null");
        Objects.requireNonNull(subject, "Audit subject must not be null");
        Objects.requireNonNull(provider, "Auth provider must not be null");

        // NO_OP is allowed for any event
        if (outcome == AuditOutcome.FAILURE && !eventAllowsFailure(event)) {
            throw new IllegalArgumentException("Failure outcome not allowed for event: " + event);
        }

        if (outcome == AuditOutcome.FAILURE && failureReason == null) {
            throw new IllegalArgumentException("Failure outcome requires failureReason for event: " + event);
        }

        if (outcome == AuditOutcome.SUCCESS && failureReason != null) {
            throw new IllegalArgumentException("Success outcome must not include failureReason for event: " + event);
        }

        if (log.isDebugEnabled()) {
            log.debug("AUDIT invariants validated | event={} outcome={}", event, outcome);
        }
    }

    /* ============================================================
       SEVERITY
       ============================================================ */

    private AuditSeverity determineSeverity(
            AuditOutcome outcome,
            AuthFailureReason failureReason
    ) {
        return switch (outcome) {
            case SUCCESS, NO_OP -> AuditSeverity.LOW;
            case FAILURE -> failureReason != null ? failureReason.getSeverity() : AuditSeverity.MEDIUM;
        };
    }

    /* ============================================================
       EVENT RULES
       ============================================================ */

    /**
     * Events that represent terminal success states
     * and must never be recorded as FAILURE.
     */
    private boolean eventAllowsFailure(AuthAuditEvent event) {
        return switch (event) {
            case LOGIN,
                 REGISTER,
                 EMAIL_VERIFICATION,
                 OAUTH_LOGIN,
                 TOKEN_REFRESH,
                 PASSWORD_CHANGE,
                 PASSWORD_RESET,
                 TOKEN_INTROSPECTION -> false;
            default -> true;
        };
    }
}
