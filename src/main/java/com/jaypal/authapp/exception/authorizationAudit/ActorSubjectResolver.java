package com.jaypal.authapp.exception.authorizationAudit;

import com.jaypal.authapp.domain.audit.entity.AuditActor;
import com.jaypal.authapp.domain.audit.entity.AuditSubject;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Dedicated component for resolving actor and subject from security context.
 * Follows Single Responsibility Principle.
 */
@Slf4j
@Component
public class ActorSubjectResolver {

    private static final String ANONYMOUS_USER = "anonymousUser";

    /**
     * Resolves the current authenticated actor from the security context.
     */
    public AuditActor resolveActor() {
        return extractPrincipalId()
                .map(userId -> AuditActor.userId(userId.toString()))
                .orElse(AuditActor.system());
    }

    /**
     * Resolves the subject (target user) from the security context.
     */
    public AuditSubject resolveSubject() {
        return extractPrincipalId()
                .map(userId -> AuditSubject.userId(userId.toString()))
                .orElse(AuditSubject.anonymous());
    }

    private Optional<java.util.UUID> extractPrincipalId() {
        try {
            return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                    .filter(Authentication::isAuthenticated)
                    .map(Authentication::getPrincipal)
                    .filter(this::isNotAnonymous)
                    .filter(AuthPrincipal.class::isInstance)
                    .map(AuthPrincipal.class::cast)
                    .map(AuthPrincipal::getUserId);

        } catch (Exception ex) {
            log.debug("Failed to extract principal from security context", ex);
            return Optional.empty();
        }
    }

    private boolean isNotAnonymous(Object principal) {
        return !(principal instanceof String str && ANONYMOUS_USER.equals(str));
    }
}