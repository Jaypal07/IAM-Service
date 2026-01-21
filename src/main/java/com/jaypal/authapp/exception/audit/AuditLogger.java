package com.jaypal.authapp.exception.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.util.*;


@Slf4j
@Component
@RequiredArgsConstructor
public class AuditLogger {

    private final AuthAuditService auditService;
    private final ObjectMapper objectMapper;

    /**
     * Records an authorization denial event with full context.
     */
    public void logAccessDenied(Exception ex, WebRequest request) {
        safeAudit(() -> {
            AuditActor actor = resolveActor();
            AuditSubject subject = resolveSubject();
            String details = buildAuthorizationDetails(ex, request);

            auditService.record(
                    AuditCategory.AUTHORIZATION,
                    AuthAuditEvent.ACCESS_DENIED,
                    AuditOutcome.FAILURE,
                    actor,
                    subject,
                    AuthFailureReason.ACCESS_DENIED,
                    AuthProvider.SYSTEM,
                    AuditContextHolder.getContext(),
                    details
            );

            log.warn(
                    "AUTHORIZATION DENIED | actor={} subject={} exception={}",
                    actor,
                    subject,
                    ex.getClass().getSimpleName()
            );
        });
    }

    /**
     * Resolves the current authenticated actor from the security context.
     */
    private AuditActor resolveActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return AuditActor.system();
        }

        Object principal = auth.getPrincipal();
        if (principal instanceof AuthPrincipal p) {
            return AuditActor.userId(p.getUserId().toString());
        }

        return AuditActor.system();
    }

    /**
     * Resolves the subject (target user) from the security context.
     */
    private AuditSubject resolveSubject() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return AuditSubject.anonymous();
        }

        Object principal = auth.getPrincipal();
        if (principal instanceof AuthPrincipal p) {
            return AuditSubject.userId(p.getUserId().toString());
        }

        return AuditSubject.anonymous();
    }

    /**
     * Builds detailed JSON context for authorization failures.
     */
    private String buildAuthorizationDetails(Exception ex, WebRequest request) {
        Set<String> permissions = extractPermissions(ex);
        String path = extractPath(request);

        try {
            Map<String, Object> details = Map.of(
                    "permissions", List.copyOf(permissions),
                    "path", path
            );
            return objectMapper.writeValueAsString(details);
        } catch (Exception e) {
            log.error("Failed to serialize authorization details", e);
            return null;
        }
    }

    /**
     * Extracts permission information from authorization exceptions.
     */
    private Set<String> extractPermissions(Exception ex) {
        Set<String> permissions = new LinkedHashSet<>();

        if (ex instanceof AuthorizationDeniedException ade) {
            String raw = ade.getAuthorizationResult().toString();
            extractAuthorities(raw, "hasAuthority", permissions);
            extractAuthorities(raw, "hasAnyAuthority", permissions);
        }

        if (permissions.isEmpty()) {
            permissions.add("UNKNOWN");
        }

        return permissions;
    }

    /**
     * Extracts authority strings from Spring Security authorization expressions.
     */
    private void extractAuthorities(String raw, String function, Set<String> permissions) {
        String token = function + "(";
        int idx = raw.indexOf(token);
        if (idx < 0) return;

        int start = raw.indexOf("(", idx) + 1;
        int end = raw.indexOf(")", start);
        if (end <= start) return;

        String content = raw.substring(start, end);

        for (String part : content.split(",")) {
            String p = part.replace("'", "").replace("\"", "").trim();
            if (!p.isBlank()) {
                permissions.add(p);
            }
        }
    }

    /**
     * Extracts the request path from the web request.
     */
    private String extractPath(WebRequest request) {
        if (request instanceof ServletWebRequest swr) {
            return swr.getRequest().getRequestURI();
        }
        return "N/A";
    }


    /**
     * Safely executes audit operations with exception handling.
     * Ensures audit failures never break the request flow.
     */
    private void safeAudit(Runnable auditOperation) {
        try {
            auditOperation.run();
        } catch (Exception auditEx) {
            log.error("Failed to audit event - audit failure must not break request flow", auditEx);
        }
    }
}