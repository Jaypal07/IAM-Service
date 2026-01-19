package com.jaypal.authapp.common.aspect;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
import com.jaypal.authapp.exception.auth.EmailAlreadyVerifiedException;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.audit.resolver.FailureReasonResolver;
import com.jaypal.authapp.infrastructure.audit.resolver.IdentityResolver;
import com.jaypal.authapp.infrastructure.audit.resolver.SubjectResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AuthAuditAspect {

    private final AuthAuditService auditService;
    private final FailureReasonResolver failureReasonResolver;
    private final IdentityResolver identityResolver;
    private final SubjectResolver subjectResolver;

    /* ============================================================
       SUCCESS HANDLING
       ============================================================ */
    @AfterReturning(pointcut = "@annotation(authAudit)", returning = "result")
    public void afterSuccess(JoinPoint joinPoint, AuthAudit authAudit, Object result) {
        AuditOutcome outcome = determineOutcome(result);

        log.debug(
                "AuthAudit SUCCESS intercepted: event={}, resolvedOutcome={}, method={}",
                authAudit.event(),
                outcome,
                joinPoint.getSignature().toShortString()
        );

        record(joinPoint, authAudit, result, null, outcome);
    }

    /* ============================================================
       FAILURE / NO-OP HANDLING
       ============================================================ */
    @AfterThrowing(pointcut = "@annotation(authAudit)", throwing = "ex")
    public void afterFailure(JoinPoint joinPoint, AuthAudit authAudit, Throwable ex) {

        // Idempotent NO_OP: already verified email
        if (ex instanceof EmailAlreadyVerifiedException) {
            log.info(
                    "AuthAudit NO_OP (idempotent): event={}, reason=EMAIL_ALREADY_VERIFIED",
                    authAudit.event()
            );

            record(joinPoint, authAudit, null, null, AuditOutcome.NO_OP);
            return;
        }

        AuthFailureReason reason = failureReasonResolver.resolve(ex);

        log.debug(
                "AuthAudit FAILURE: event={}, reason={}, exception={}",
                authAudit.event(),
                reason,
                ex.getClass().getSimpleName()
        );

        record(joinPoint, authAudit, null, reason, AuditOutcome.FAILURE);
    }

    /* ============================================================
       CORE AUDIT RECORDING
       ============================================================ */
    private void record(
            JoinPoint joinPoint,
            AuthAudit authAudit,
            Object result,
            AuthFailureReason failureReason,
            AuditOutcome outcome
    ) {
        try {
            AuditSubject subject = (outcome != AuditOutcome.FAILURE)
                    ? resolveSubject(joinPoint, authAudit, result)
                    : resolveSubjectSafely(joinPoint, authAudit);

            AuditRequestContext context = AuditContextHolder.getContext();
            AuditCategory category = resolveCategory(authAudit.event());

            auditService.record(
                    category,
                    authAudit.event(),
                    outcome,
                    subject,
                    failureReason,
                    authAudit.provider(),
                    context
            );

            log.info(
                    "Audit recorded: event={}, outcome={}, category={}, subjectType={}",
                    authAudit.event(),
                    outcome,
                    category,
                    subject.getType()
            );

        } catch (Exception auditEx) {
            log.error(
                    "Audit recording FAILED: event={}, outcome={}",
                    authAudit.event(),
                    outcome,
                    auditEx
            );
        }
    }

    /* ============================================================
       OUTCOME DETERMINATION
       ============================================================ */
    private AuditOutcome determineOutcome(Object result) {

        // Context-level NO_OP (business decision)
        if (AuditContextHolder.isNoOp()) {
            log.debug("Audit outcome overridden to NO_OP via AuditContextHolder");
            return AuditOutcome.NO_OP;
        }

        // Return-based NO_OP
        if (result == null) {
            return AuditOutcome.NO_OP;
        }

        if (result instanceof Boolean b && !b) {
            return AuditOutcome.NO_OP;
        }

        return AuditOutcome.SUCCESS;
    }


    /* ============================================================
       SUBJECT RESOLUTION
       ============================================================ */
    private AuditSubject resolveSubject(
            JoinPoint joinPoint,
            AuthAudit authAudit,
            Object result
    ) {
        UUID userId = identityResolver.fromSecurityContext();
        if (userId != null) {
            return AuditSubject.userId(userId.toString());
        }

        if (result != null) {
            UUID fromResult = identityResolver.fromResult(result);
            if (fromResult != null) {
                return AuditSubject.userId(fromResult.toString());
            }
        }

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        return subjectResolver.resolve(
                authAudit,
                joinPoint.getArgs(),
                signature.getParameterNames()
        );
    }

    private AuditSubject resolveSubjectSafely(
            JoinPoint joinPoint,
            AuthAudit authAudit
    ) {
        try {
            return resolveSubject(joinPoint, authAudit, null);
        } catch (Exception ex) {
            log.warn(
                    "Audit subject resolution failed, defaulting to ANONYMOUS: event={}",
                    authAudit.event(),
                    ex
            );
            return AuditSubject.anonymous();
        }
    }

    /* ============================================================
       CATEGORY RESOLUTION
       ============================================================ */
    private AuditCategory resolveCategory(AuthAuditEvent event) {
        return switch (event) {
            case LOGIN, LOGOUT_SINGLE_SESSION, LOGOUT_ALL_SESSIONS, REGISTER,
                 EMAIL_VERIFICATION, EMAIL_VERIFICATION_RESEND, OAUTH_LOGIN,
                 TOKEN_ISSUED, TOKEN_REFRESH, TOKEN_REVOKED_SINGLE, TOKEN_REVOKED_ALL ->
                    AuditCategory.AUTHENTICATION;

            case TOKEN_INTROSPECTION, RATE_LIMIT_EXCEEDED,
                 SECURITY_POLICY_VIOLATION, SYSTEM_ERROR ->
                    AuditCategory.SYSTEM;

            case PASSWORD_CHANGE, PASSWORD_RESET_REQUESTED, PASSWORD_RESET,
                 ACCOUNT_VIEWED_SELF, ACCOUNT_UPDATED_SELF,
                 ACCOUNT_DISABLED_BY_ADMIN, ACCOUNT_DELETED_SELF,
                 ACCOUNT_LOCKED, ACCOUNT_UNLOCKED ->
                    AuditCategory.ACCOUNT;

            case ROLE_ASSIGNED, ROLE_REMOVED, PERMISSION_GRANTED,
                 PERMISSION_REVOKED, ACCESS_DENIED ->
                    AuditCategory.AUTHORIZATION;

            case ADMIN_USER_CREATED, ADMIN_USER_UPDATED, ADMIN_USER_DELETED,
                 ADMIN_USER_VIEWED, ADMIN_USER_LISTED,
                 ADMIN_ROLE_MODIFIED, ADMIN_PERMISSION_MODIFIED,
                 ADMIN_ACTION_GENERIC ->
                    AuditCategory.ADMIN;
        };
    }
}
