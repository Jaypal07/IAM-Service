package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.context.AuditContext;
import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class IdentityResolver {

    public UUID resolveFromContext() {

        UUID ctxUserId = AuditContext.getUserId();
        if (ctxUserId != null) {
            return ctxUserId;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AuthPrincipal principal) {
            return principal.getUserId();
        }

        return null;
    }

    public UUID resolveFromResult(Object result) {

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
