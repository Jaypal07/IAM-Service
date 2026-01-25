package com.jaypal.authapp.exception.authorizationAudit;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Dedicated component for building authorization failure details.
 * Follows Single Responsibility Principle.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthorizationDetailsBuilder {

    private final ObjectMapper objectMapper;
    private final PermissionExtractor permissionExtractor;
    private final RequestPathExtractor requestPathExtractor;

    /**
     * Builds detailed JSON context for authorization failures.
     */
    public String build(Exception ex, WebRequest request) {
        try {
            Set<String> permissions = permissionExtractor.extract(ex);
            String path = requestPathExtractor.extract(request);

            Map<String, Object> details = Map.of(
                    "missing permissions", List.copyOf(permissions),
                    "path", path
            );

            return objectMapper.writeValueAsString(details);

        } catch (Exception e) {
            log.error("Failed to serialize authorization details", e);
            return null;
        }
    }
}