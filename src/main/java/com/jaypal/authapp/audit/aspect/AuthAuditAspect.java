package com.jaypal.authapp.audit.aspect;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.application.AuditRequestContext;
import com.jaypal.authapp.audit.application.AuthAuditService;
import com.jaypal.authapp.audit.context.AuditContextHolder;
import com.jaypal.authapp.audit.domain.*;
import com.jaypal.authapp.audit.resolver.FailureReasonResolver;
import com.jaypal.authapp.audit.resolver.IdentityResolver;
import com.jaypal.authapp.audit.resolver.SubjectResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AuthAuditAspect {

    private final AuthAuditService auditService;
    private final FailureReasonResolver failureResolver;
    private final IdentityResolver identityResolver;
    private final SubjectResolver subjectResolver;

    @AfterReturning(pointcut = "@annotation(authAudit)", returning = "result")
    public void success(JoinPoint jp, AuthAudit authAudit, Object result) {
        try {
            final AuditSubject subject = resolveSubject(jp, authAudit, result);
            final AuditRequestContext context = AuditContextHolder.getContext();

            auditService.record(
                    resolveCategory(authAudit.event()),
                    authAudit.event(),
                    AuditOutcome.SUCCESS,
                    subject,
                    null,
                    authAudit.provider(),
                    context
            );
        } catch (Exception ex) {
            log.error("Failed to record audit success event: {}", authAudit.event(), ex);
        }
    }

    @AfterThrowing(pointcut = "@annotation(authAudit)", throwing = "ex")
    public void failure(JoinPoint jp, AuthAudit authAudit, Throwable ex) {
        try {
            final AuthFailureReason reason = failureResolver.resolve(ex);
            final AuditSubject subject = resolveSubjectSafely(jp, authAudit);
            final AuditRequestContext context = AuditContextHolder.getContext();

            auditService.record(
                    resolveCategory(authAudit.event()),
                    authAudit.event(),
                    AuditOutcome.FAILURE,
                    subject,
                    reason,
                    authAudit.provider(),
                    context
            );
        } catch (Exception auditEx) {
            log.error("Failed to record audit failure event: {} (original: {})",
                    authAudit.event(), ex.getClass().getSimpleName(), auditEx);
        }
    }

    private AuditSubject resolveSubject(
            JoinPoint jp,
            AuthAudit authAudit,
            Object result
    ) {
        final UUID userId = identityResolver.fromSecurityContext();
        if (userId != null) {
            return AuditSubject.userId(userId.toString());
        }

        final UUID fromResult = result != null
                ? identityResolver.fromResult(result)
                : null;

        if (fromResult != null) {
            return AuditSubject.userId(fromResult.toString());
        }

        final MethodSignature sig = (MethodSignature) jp.getSignature();

        return subjectResolver.resolve(
                authAudit,
                jp.getArgs(),
                sig.getParameterNames()
        );
    }

    private AuditSubject resolveSubjectSafely(JoinPoint jp, AuthAudit authAudit) {
        try {
            return resolveSubject(jp, authAudit, null);
        } catch (Exception ex) {
            log.warn("Failed to resolve audit subject for failure event, using ANONYMOUS: {}",
                    authAudit.event(), ex);
            return AuditSubject.anonymous();
        }
    }

    private AuditCategory resolveCategory(AuthAuditEvent event) {
        return switch (event) {
            case LOGIN, LOGOUT, REGISTER,
                 EMAIL_VERIFY, EMAIL_VERIFICATION_RESEND,
                 OAUTH_LOGIN,
                 TOKEN_ISSUED, TOKEN_REFRESHED, TOKEN_REVOKED
                    -> AuditCategory.AUTHENTICATION;

            case PASSWORD_CHANGE,
                 PASSWORD_RESET_REQUEST,
                 PASSWORD_RESET_RESULT,
                 ACCOUNT_UPDATED,
                 ACCOUNT_DISABLED
                    -> AuditCategory.ACCOUNT;

            case ROLE_ASSIGNED,
                 ROLE_REMOVED,
                 PERMISSION_GRANTED,
                 PERMISSION_REVOKED
                    -> AuditCategory.AUTHORIZATION;

            case ADMIN_USER_CREATED,
                 ADMIN_USER_UPDATED,
                 ADMIN_USER_DELETED,
                 TOKEN_INTROSPECTED
                    -> AuditCategory.ADMIN;
        };
    }
}

/*
CHANGELOG:
1. CRITICAL FIX: Now retrieves context from AuditContextHolder instead of passing null
2. Added try-catch around aspect logic to prevent audit failures from breaking business logic
3. Added resolveSubjectSafely for failure cases (falls back to ANONYMOUS)
4. Added comprehensive error logging for debugging
5. Context is now properly propagated from HTTP filter through async thread
6. Added @Slf4j for logging
*/