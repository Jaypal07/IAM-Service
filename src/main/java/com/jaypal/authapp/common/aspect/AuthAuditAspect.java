package com.jaypal.authapp.common.aspect;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.audit.domain.*;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.infrastructure.audit.resolver.FailureReasonResolver;
import com.jaypal.authapp.infrastructure.audit.resolver.IdentityResolver;
import com.jaypal.authapp.infrastructure.audit.resolver.SubjectResolver;
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

            case LOGIN_SUCCESS, LOGIN_FAILURE,
                 LOGOUT_SINGLE_SESSION, LOGOUT_ALL_SESSIONS,
                 REGISTER_SUCCESS, REGISTER_FAILURE,
                 EMAIL_VERIFICATION_SUCCESS, EMAIL_VERIFICATION_FAILURE,
                 EMAIL_VERIFICATION_RESEND,
                 OAUTH_LOGIN_SUCCESS, OAUTH_LOGIN_FAILURE,
                 TOKEN_ISSUED, TOKEN_REFRESH_SUCCESS, TOKEN_REFRESH_FAILURE,
                 TOKEN_REVOKED_SINGLE, TOKEN_REVOKED_ALL
                    -> AuditCategory.AUTHENTICATION;

            case TOKEN_INTROSPECTION_SUCCESS, TOKEN_INTROSPECTION_FAILURE, RATE_LIMIT_EXCEEDED,
                 SECURITY_POLICY_VIOLATION, SYSTEM_ERROR
                    -> AuditCategory.SYSTEM;

            case PASSWORD_CHANGE_SUCCESS, PASSWORD_CHANGE_FAILURE,
                 PASSWORD_RESET_REQUESTED, PASSWORD_RESET_REQUEST_FAILED,
                 PASSWORD_RESET_SUCCESS, PASSWORD_RESET_FAILURE,
                 ACCOUNT_VIEWED_SELF, ACCOUNT_UPDATED_SELF,
                 ACCOUNT_DISABLED_BY_ADMIN, ACCOUNT_DELETED_SELF,
                 ACCOUNT_LOCKED, ACCOUNT_UNLOCKED
                    -> AuditCategory.ACCOUNT;

            case ROLE_ASSIGNED, ROLE_REMOVED,
                 PERMISSION_GRANTED, PERMISSION_REVOKED,
                 ACCESS_DENIED
                    -> AuditCategory.AUTHORIZATION;

            case ADMIN_USER_CREATED, ADMIN_USER_UPDATED,
                 ADMIN_USER_DELETED, ADMIN_USER_VIEWED,
                 ADMIN_USER_LISTED, ADMIN_ROLE_MODIFIED,
                 ADMIN_PERMISSION_MODIFIED, ADMIN_ACTION_GENERIC
                    -> AuditCategory.ADMIN;

        };
    }

}