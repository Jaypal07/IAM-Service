package com.jaypal.authapp.domain.audit.service;

import com.jaypal.authapp.audit.domain.*;
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
        if (log.isDebugEnabled()) {
            log.debug(
                    "AUDIT invoked | thread={} category={} event={} outcome={} subject={} failureReason={} provider={} context={}",
                    Thread.currentThread().getName(),
                    category,
                    event,
                    outcome,
                    subject,
                    failureReason,
                    provider,
                    context
            );
        }

        try {
            if (log.isDebugEnabled()) {
                log.debug("AUDIT enforcing invariants | event={}", event);
            }

            enforceInvariants(outcome, failureReason, subject, category, event, provider);

            AuditSeverity severity = determineSeverity(outcome, failureReason);

            if (log.isDebugEnabled()) {
                log.debug(
                        "AUDIT severity resolved | event={} outcome={} failureReason={} severity={}",
                        event,
                        outcome,
                        failureReason,
                        severity
                );
            }

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

            if (log.isDebugEnabled()) {
                log.debug("AUDIT entity created | auditLog={}", auditLog);
            }

            AuthAuditLog saved = repository.save(auditLog);

            log.info(
                    "AUDIT persisted | auditId={} event={} outcome={} severity={}",
                    saved.getId(),
                    event,
                    outcome,
                    severity
            );

            if (outcome == AuditOutcome.FAILURE
                    && failureReason != null
                    && failureReason.getSeverity() == AuditSeverity.CRITICAL) {

                log.warn(
                        "AUDIT CRITICAL | event={} subject={} failureReason={} provider={} context={}",
                        event,
                        subject,
                        failureReason,
                        provider,
                        context
                );
            }

        } catch (Exception ex) {
            log.error(
                    "AUDIT failed | event={} outcome={} subject={} provider={} context={}",
                    event,
                    outcome,
                    subject,
                    provider,
                    context,
                    ex
            );

            failureMonitor.onAuditFailure(event, ex);
        }
    }

    private void enforceInvariants(
            AuditOutcome outcome,
            AuthFailureReason failureReason,
            AuditSubject subject,
            AuditCategory category,
            AuthAuditEvent event,
            AuthProvider provider
    ) {
        if (log.isDebugEnabled()) {
            log.debug(
                    "AUDIT invariant check | category={} event={} outcome={} subject={} failureReason={} provider={}",
                    category,
                    event,
                    outcome,
                    subject,
                    failureReason,
                    provider
            );
        }

        Objects.requireNonNull(category, "Category cannot be null");
        Objects.requireNonNull(event, "Event cannot be null");
        Objects.requireNonNull(outcome, "Outcome cannot be null");
        Objects.requireNonNull(subject, "Subject cannot be null");
        Objects.requireNonNull(provider, "Provider cannot be null");

        if (outcome == AuditOutcome.FAILURE && !eventAllowsFailure(event)) {
            throw new IllegalArgumentException(
                    "Failure not allowed for event: " + event
            );
        }


        if (outcome == AuditOutcome.FAILURE && failureReason == null) {
            log.error("AUDIT invariant violation | FAILURE without failureReason event={}", event);
            throw new IllegalArgumentException(
                    "Failure outcome must include reason for event: " + event
            );
        }

        if (outcome == AuditOutcome.SUCCESS && failureReason != null) {
            log.error("AUDIT invariant violation | SUCCESS with failureReason event={}", event);
            throw new IllegalArgumentException(
                    "Success outcome must not include failure reason for event: " + event
            );
        }

        if (log.isDebugEnabled()) {
            log.debug("AUDIT invariant check passed | event={}", event);
        }
    }

    private AuditSeverity determineSeverity(
            AuditOutcome outcome,
            AuthFailureReason failureReason
    ) {
        if (log.isDebugEnabled()) {
            log.debug(
                    "AUDIT determining severity | outcome={} failureReason={}",
                    outcome,
                    failureReason
            );
        }

        if (outcome == AuditOutcome.SUCCESS) {
            return AuditSeverity.LOW;
        }

        return failureReason != null
                ? failureReason.getSeverity()
                : AuditSeverity.MEDIUM;
    }

    private boolean eventAllowsFailure(AuthAuditEvent event) {
        return switch (event) {
            case LOGIN_SUCCESS,
                 REGISTER_SUCCESS,
                 EMAIL_VERIFICATION_SUCCESS,
                 OAUTH_LOGIN_SUCCESS,
                 TOKEN_REFRESH_SUCCESS,
                 PASSWORD_CHANGE_SUCCESS,
                 PASSWORD_RESET_SUCCESS,
                 TOKEN_INTROSPECTION_SUCCESS
                    -> false;
            default -> true;
        };
    }

}
