package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
public class IdentityResolver {

    public UUID fromSecurityContext() {
        try {
            final Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (auth == null || !auth.isAuthenticated()) {
                return null;
            }

            if ("anonymousUser".equals(auth.getPrincipal())) {
                return null;
            }

            if (auth.getPrincipal() instanceof AuthPrincipal principal) {
                return principal.getUserId();
            }

            return null;

        } catch (Exception ex) {
            log.debug("Failed to extract user ID from security context", ex);
            return null;
        }
    }

    public UUID fromResult(Object result) {
        try {
            if (result instanceof ResponseEntity<?> responseEntity) {
                final Object body = responseEntity.getBody();

                if (body instanceof TokenResponse tokenResponse) {
                    return tokenResponse.user().id();
                }
            }

            if (result instanceof AuthLoginResult authLoginResult) {
                return authLoginResult.user().id();
            }

            return null;

        } catch (Exception ex) {
            log.debug("Failed to extract user ID from result", ex);
            return null;
        }
    }
}

/*
CHANGELOG:
1. Added null checks and try-catch to prevent NPE
2. Added check for "anonymousUser" string (Spring Security default)
3. Added logging for debugging
4. Made all methods safe - return null instead of throwing
5. Added explicit type checks before casting
6. Improved code readability with final variables
*/