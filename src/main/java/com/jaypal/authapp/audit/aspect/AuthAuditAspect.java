package com.jaypal.authapp.audit.aspect;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.context.AuditContext;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuthFailureReason;
import com.jaypal.authapp.audit.resolver.*;
import com.jaypal.authapp.audit.application.AuthAuditService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Aspect
@Component
@RequiredArgsConstructor
public class AuthAuditAspect {

    private final AuthAuditService auditService;
    private final FailureReasonResolver failureResolver;
    private final IdentityResolver identityResolver;
    private final SubjectResolver subjectResolver;
    private final HttpServletRequest request;

    @AfterReturning(
            pointcut = "@annotation(authAudit)",
            returning = "result"
    )
    public void success(
            JoinPoint jp,
            AuthAudit authAudit,
            Object result
    ) {
        try {
            UUID userId = identityResolver.resolveFromContext();
            if (userId == null) {
                userId = identityResolver.resolveFromResult(result);
            }

            String subject = userId == null
                    ? subjectResolver.resolve(authAudit, jp.getArgs())
                    : null;

            auditService.log(
                    userId,
                    subject,
                    authAudit.event(),
                    authAudit.provider(),
                    request,
                    true,
                    null
            );
        } finally {
            AuditContext.clear();
        }
    }

    @AfterThrowing(
            pointcut = "@annotation(authAudit)",
            throwing = "ex"
    )
    public void failure(
            JoinPoint jp,
            AuthAudit authAudit,
            Throwable ex
    ) {
        try {
            AuthAuditEvent event = mapFailureEvent(authAudit.event());
            AuthFailureReason reason = failureResolver.resolve(event, ex);

            UUID userId = identityResolver.resolveFromContext();
            String subject = userId == null
                    ? subjectResolver.resolve(authAudit, jp.getArgs())
                    : null;

            auditService.log(
                    userId,
                    subject,
                    event,
                    authAudit.provider(),
                    request,
                    false,
                    reason
            );
        } finally {
            AuditContext.clear();
        }
    }

    private AuthAuditEvent mapFailureEvent(AuthAuditEvent successEvent) {
        return switch (successEvent) {
            case LOGIN_SUCCESS -> AuthAuditEvent.LOGIN_FAILURE;
            case OAUTH_LOGIN_SUCCESS -> AuthAuditEvent.OAUTH_LOGIN_FAILURE;
            case PASSWORD_RESET_SUCCESS -> AuthAuditEvent.PASSWORD_RESET_FAILURE;
            default -> successEvent;
        };
    }
}
