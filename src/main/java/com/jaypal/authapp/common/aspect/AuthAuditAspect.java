package com.jaypal.authapp.common.aspect;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.domain.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
import com.jaypal.authapp.exception.auth.EmailAlreadyVerifiedException;
import com.jaypal.authapp.exception.auth.EmailNotRegisteredException;
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

/**
 * Refactored AuthAuditAspect with improved separation of concerns.
 * Each responsibility is clearly delineated and delegated.
 */
@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AuthAuditAspect {

    private final AuthAuditService auditService;
    private final FailureReasonResolver failureReasonResolver;
    private final IdentityResolver identityResolver;
    private final SubjectResolver subjectResolver;
    private final AuditCategoryResolver categoryResolver;
    private final AuditOutcomeResolver outcomeResolver;

    @AfterReturning(pointcut = "@annotation(authAudit)", returning = "result")
    public void afterSuccess(JoinPoint joinPoint, AuthAudit authAudit, Object result) {
        AuditOutcome outcome = outcomeResolver.determineOutcome(result);

        log.debug(
                "AuthAudit SUCCESS intercepted: event={}, resolvedOutcome={}, method={}",
                authAudit.event(),
                outcome,
                joinPoint.getSignature().toShortString()
        );

        record(joinPoint, authAudit, result, null, outcome);
    }

    @AfterThrowing(pointcut = "@annotation(authAudit)", throwing = "ex")
    public void afterFailure(JoinPoint joinPoint, AuthAudit authAudit, Throwable ex) {

        // Handle idempotent NO_OP cases
        if (isIdempotentNoOp(ex, authAudit)) {
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

    private boolean isIdempotentNoOp(Throwable ex, AuthAudit authAudit) {
        if (ex instanceof EmailAlreadyVerifiedException) {
            log.info(
                    "AuthAudit NO_OP (idempotent): event={}, reason=EMAIL_ALREADY_VERIFIED",
                    authAudit.event()
            );
            return true;
        }

        if (ex instanceof EmailAlreadyExistsException) {
            log.info(
                    "AuthAudit NO_OP (idempotent): event={}, reason=EMAIL_ALREADY_EXISTS",
                    authAudit.event()
            );
            return true;
        }

        if (ex instanceof EmailNotRegisteredException) {
            log.info(
                    "AuthAudit NO_OP (idempotent): event={}, reason=EMAIL_NOT_REGISTERED",
                    authAudit.event()
            );
            return true;
        }

        return false;
    }

    private void record(
            JoinPoint joinPoint,
            AuthAudit authAudit,
            Object result,
            AuthFailureReason failureReason,
            AuditOutcome outcome
    ) {
        try {
            AuditSubject subject = resolveSubjectForOutcome(joinPoint, authAudit, result, outcome);
            AuditRequestContext context = AuditContextHolder.getContext();
            AuditCategory category = categoryResolver.resolve(authAudit.event());
            AuditActor actor = resolveActor();

            auditService.record(
                    category,
                    authAudit.event(),
                    outcome,
                    actor,
                    subject,
                    failureReason,
                    authAudit.provider(),
                    context
            );

            log.info(
                    "Audit recorded: event={}, outcome={}, actor={}, category={}, subjectType={}",
                    authAudit.event(),
                    outcome,
                    actor,
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

    private AuditSubject resolveSubjectForOutcome(
            JoinPoint joinPoint,
            AuthAudit authAudit,
            Object result,
            AuditOutcome outcome
    ) {
        return outcome != AuditOutcome.FAILURE
                ? resolveSubject(joinPoint, authAudit, result)
                : resolveSubjectSafely(joinPoint, authAudit);
    }

    private AuditActor resolveActor() {
        UUID userId = identityResolver.fromSecurityContext();
        return userId != null
                ? AuditActor.userId(userId.toString())
                : AuditActor.system();
    }

    private AuditSubject resolveSubject(
            JoinPoint joinPoint,
            AuthAudit authAudit,
            Object result
    ) {
        // Try security context first
        UUID userId = identityResolver.fromSecurityContext();
        if (userId != null) {
            return AuditSubject.userId(userId.toString());
        }

        // Try result extraction
        if (result != null) {
            UUID fromResult = identityResolver.fromResult(result);
            if (fromResult != null) {
                return AuditSubject.userId(fromResult.toString());
            }
        }

        // Fall back to parameter resolution
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        return subjectResolver.resolve(
                authAudit,
                joinPoint.getArgs(),
                signature.getParameterNames()
        );
    }

    private AuditSubject resolveSubjectSafely(JoinPoint joinPoint, AuthAudit authAudit) {
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
}