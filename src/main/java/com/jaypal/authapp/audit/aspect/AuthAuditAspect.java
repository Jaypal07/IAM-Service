package com.jaypal.authapp.audit.aspect;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.service.AuthAuditService;
import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Aspect
@Component
@RequiredArgsConstructor
public class AuthAuditAspect {

    private final AuthAuditService auditService;
    private final HttpServletRequest request;

    @Around("@annotation(authAudit)")
    public Object audit(ProceedingJoinPoint pjp, AuthAudit authAudit) throws Throwable {

        Object result = pjp.proceed();

        UUID userId = extractUserIdFromResult(result);

        auditService.log(
                userId,
                authAudit.event(),
                authAudit.provider(),
                request,
                true,
                null
        );

        return result;
    }

    private UUID extractUserIdFromResult(Object result) {

        if (result instanceof ResponseEntity<?> response) {
            Object body = response.getBody();

            if (body instanceof TokenResponse tokenResponse) {
                return tokenResponse.user().id();
            }
        }

        if (result instanceof AuthLoginResult authResult) {
            return authResult.user().getId();
        }

        return null;
    }

}
