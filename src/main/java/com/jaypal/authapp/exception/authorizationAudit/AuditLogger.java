package com.jaypal.authapp.exception.authorizationAudit;

import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

/**
 * Refactored AuditLogger following SOLID principles.
 * Delegates specific responsibilities to focused components.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuditLogger {

    private final AuthAuditService auditService;
    private final ActorSubjectResolver actorSubjectResolver;
    private final AuthorizationDetailsBuilder authorizationDetailsBuilder;

    /**
     * Records an authorization denial event with full context.
     */
    public void logAccessDenied(Exception ex, WebRequest request) {
        safeAudit(() -> recordAccessDenied(ex, request));
    }

    private void recordAccessDenied(Exception ex, WebRequest request) {
        AuditActor actor = actorSubjectResolver.resolveActor();
        AuditSubject subject = actorSubjectResolver.resolveSubject();
        String details = authorizationDetailsBuilder.build(ex, request);

        auditService.record(
                AuditCategory.AUTHORIZATION,
                AuthAuditEvent.ACCESS_DENIED,
                AuditOutcome.FAILURE,
                actor,
                subject,
                AuthFailureReason.ACCESS_DENIED,
                AuthProvider.SYSTEM,
                AuditContextHolder.getContext(),
                details
        );

        log.warn(
                "AUTHORIZATION DENIED | actor={} subject={} exception={}",
                actor,
                subject,
                ex.getClass().getSimpleName()
        );
    }

    /**
     * Safely executes audit operations with exception handling.
     * Ensures audit failures never break the request flow.
     */
    private void safeAudit(Runnable auditOperation) {
        try {
            auditOperation.run();
        } catch (Exception auditEx) {
            log.error("Failed to audit event - audit failure must not break request flow", auditEx);
        }
    }
}