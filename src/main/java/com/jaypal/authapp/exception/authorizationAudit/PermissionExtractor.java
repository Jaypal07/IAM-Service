package com.jaypal.authapp.exception.authorizationAudit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Extracts permission information from authorization exceptions.
 * Follows Single Responsibility Principle.
 */
@Slf4j
@Component
public class PermissionExtractor {

    private static final String UNKNOWN_PERMISSION = "UNKNOWN";
    private static final String HAS_AUTHORITY = "hasAuthority";
    private static final String HAS_ANY_AUTHORITY = "hasAnyAuthority";

    public Set<String> extract(Exception ex) {
        Set<String> permissions = new LinkedHashSet<>();

        if (ex instanceof AuthorizationDeniedException ade) {
            String rawAuthResult = ade.getAuthorizationResult().toString();
            extractAuthoritiesFromExpression(rawAuthResult, HAS_AUTHORITY, permissions);
            extractAuthoritiesFromExpression(rawAuthResult, HAS_ANY_AUTHORITY, permissions);
        }

        return permissions.isEmpty()
                ? Set.of(UNKNOWN_PERMISSION)
                : permissions;
    }

    /**
     * Extracts authority strings from Spring Security authorization expressions.
     */
    private void extractAuthoritiesFromExpression(
            String expression,
            String function,
            Set<String> permissions
    ) {
        String functionToken = function + "(";
        int functionIndex = expression.indexOf(functionToken);

        if (functionIndex < 0) {
            return;
        }

        int startIndex = expression.indexOf("(", functionIndex) + 1;
        int endIndex = expression.indexOf(")", startIndex);

        if (endIndex <= startIndex) {
            return;
        }

        String content = expression.substring(startIndex, endIndex);
        parseAuthorities(content, permissions);
    }

    private void parseAuthorities(String content, Set<String> permissions) {
        for (String part : content.split(",")) {
            String cleaned = cleanAuthority(part);
            if (!cleaned.isBlank()) {
                permissions.add(cleaned);
            }
        }
    }

    private String cleanAuthority(String authority) {
        return authority
                .replace("'", "")
                .replace("\"", "")
                .trim();
    }
}