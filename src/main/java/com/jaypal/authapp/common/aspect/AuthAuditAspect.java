package com.jaypal.authapp.common.aspect;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
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
    private final AuditCategoryResolver categoryResolver;
    private final AuditOutcomeResolver outcomeResolver;

    @AfterReturning(pointcut = "@annotation(authAudit)", returning = "result")
    public void afterSuccess(JoinPoint joinPoint, AuthAudit authAudit, Object result) {
        AuditOutcome outcome = outcomeResolver.fromResult(result);
        AuthFailureReason failureReason =
                outcome == AuditOutcome.REJECTION
                        ? AuditContextHolder.getRejectionReason()
                        : null;

        log.debug(
                "AuthAudit SUCCESS intercepted: event={}, resolvedOutcome={}, method={}",
                authAudit.event(),
                outcome,
                joinPoint.getSignature().toShortString()
        );

        record(joinPoint, authAudit, result, failureReason, outcome);
    }

    @AfterThrowing(pointcut = "@annotation(authAudit)", throwing = "ex")
    public void afterFailure(JoinPoint joinPoint, AuthAudit authAudit, Throwable ex) {

        // ✅ SECURITY BOUNDARY:
        // Authorization failures are audited centrally via AuditLogger
        if (isAuthorizationException(ex)) {
            log.debug(
                    "AuthAudit skipped for authorization failure (handled by security audit): event={}, exception={}",
                    authAudit.event(),
                    ex.getClass().getSimpleName()
            );
            return;
        }

        AuditOutcome outcome = outcomeResolver.fromException(ex);
        AuthFailureReason reason = failureReasonResolver.resolve(ex);

        log.debug(
                "AuthAudit FAILURE: event={}, reason={}, exception={}",
                authAudit.event(),
                reason,
                ex.getClass().getSimpleName()
        );

        record(joinPoint, authAudit, null, reason, outcome);
    }

    private boolean isAuthorizationException(Throwable ex) {
        return ex instanceof AccessDeniedException
                || ex instanceof AuthorizationDeniedException;
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
