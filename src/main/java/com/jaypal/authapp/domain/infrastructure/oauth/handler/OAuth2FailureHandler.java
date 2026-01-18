package com.jaypal.authapp.domain.infrastructure.oauth.handler;

import com.jaypal.authapp.domain.dto.audit.AuditRequestContext;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.domain.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.config.properties.FrontendProperties;
import com.jaypal.authapp.domain.audit.entity.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2FailureHandler implements AuthenticationFailureHandler {

    private final FrontendProperties frontendProperties;
    private final AuthAuditService auditService;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException {

        Objects.requireNonNull(exception, "Authentication exception cannot be null");

        final String provider = extractProvider(request);
        final String errorCode = extractErrorCode(exception);
        final String errorMessage = sanitizeErrorMessage(exception.getMessage());

        logFailure(provider, errorCode, exception);
        auditFailure(provider, exception);

        final String redirectUrl = buildFailureRedirectUrl(errorCode, errorMessage);

        log.info("OAuth2 authentication failed - provider: {}, error: {} - redirecting to: {}",
                provider, errorCode, redirectUrl);

        response.sendRedirect(redirectUrl);
    }

    private String extractProvider(HttpServletRequest request) {
        final String requestUri = request.getRequestURI();

        if (requestUri != null && requestUri.contains("/oauth2/")) {
            final String[] parts = requestUri.split("/");
            for (int i = 0; i < parts.length - 1; i++) {
                if ("code".equals(parts[i]) && i + 1 < parts.length) {
                    return parts[i + 1];
                }
            }
        }

        return "unknown";
    }

    private String extractErrorCode(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException oauth2Ex) {
            final String errorCode = oauth2Ex.getError().getErrorCode();
            return errorCode != null ? errorCode : "unknown_error";
        }

        return exception.getClass().getSimpleName()
                .replace("Exception", "")
                .toLowerCase();
    }

    private String sanitizeErrorMessage(String message) {
        if (message == null || message.isBlank()) {
            return "Authentication failed";
        }

        if (message.length() > 200) {
            return message.substring(0, 200) + "...";
        }

        return message.replaceAll("[^a-zA-Z0-9 .,?!-]", "");
    }

    private void logFailure(String provider, String errorCode, AuthenticationException exception) {
        log.warn("OAuth2 authentication failure - provider: {}, error: {}, message: {}",
                provider, errorCode, exception.getMessage());

        if (log.isDebugEnabled()) {
            log.debug("OAuth2 authentication failure details", exception);
        }
    }

    private void auditFailure(String provider, AuthenticationException exception) {
        try {
            final AuditRequestContext context = AuditContextHolder.getContext();
            final AuthProvider auditProvider = parseAuditProvider(provider);
            final AuthFailureReason reason = mapFailureReason(exception);

            auditService.record(
                    AuditCategory.AUTHENTICATION,
                    AuthAuditEvent.OAUTH_LOGIN_FAILURE,
                    AuditOutcome.FAILURE,
                    AuditSubject.anonymous(),
                    reason,
                    auditProvider,
                    context
            );
        } catch (Exception auditEx) {
            log.error("Failed to audit OAuth failure", auditEx);
        }
    }

    private AuthProvider parseAuditProvider(String provider) {
        try {
            return AuthProvider.valueOf(provider.toUpperCase());
        } catch (IllegalArgumentException ex) {
            return AuthProvider.SYSTEM;
        }
    }

    private AuthFailureReason mapFailureReason(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException oauth2Ex) {
            final String errorCode = oauth2Ex.getError().getErrorCode();

            if (errorCode != null) {
                return switch (errorCode) {
                    case "invalid_token", "invalid_grant" -> AuthFailureReason.TOKEN_INVALID;
                    case "access_denied" -> AuthFailureReason.ACCESS_DENIED;
                    default -> AuthFailureReason.INVALID_CREDENTIALS;
                };
            }
        }

        return AuthFailureReason.INVALID_CREDENTIALS;
    }

    private String buildFailureRedirectUrl(String errorCode, String errorMessage) {
        final String baseUrl = frontendProperties.getFailureRedirect();

        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException(
                    "Frontend failure redirect URL is not configured. Set 'app.frontend.failure-redirect'");
        }

        final String encodedErrorCode = URLEncoder.encode(errorCode, StandardCharsets.UTF_8);
        final String encodedMessage = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

        final String separator = baseUrl.contains("?") ? "&" : "?";

        return String.format("%s%serror=%s&message=%s",
                baseUrl, separator, encodedErrorCode, encodedMessage);
    }
}