package com.jaypal.authapp.infrastructure.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jaypal.authapp.exception.auth.InvalidRefreshTokenException;
import com.jaypal.authapp.exception.auth.MissingRefreshTokenException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshTokenExtractor {

    private static final String REFRESH_HEADER = "X-Refresh-Token";
    private static final String REFRESH_BODY_FIELD = "refreshToken";
    private static final int MAX_TOKEN_LENGTH = 2048;

    private final CookieService cookieService;
    private final ObjectMapper objectMapper;

    /**
     * Extraction priority:
     * 1. Cookie
     * 2. Header
     * 3. JSON body
     */
    public Optional<String> extract(HttpServletRequest request) {
        log.debug("Starting refresh token extraction");

        Optional<String> token = extractFromCookie(request);
        if (token.isPresent()) {
            log.debug("Refresh token found in cookie");
            return token.map(this::validate);
        }

        token = extractFromHeader(request);
        if (token.isPresent()) {
            log.debug("Refresh token found in header '{}'", REFRESH_HEADER);
            return token.map(this::validate);
        }

        token = extractFromBody(request);
        if (token.isPresent()) {
            log.debug("Refresh token found in request body");
            return token.map(this::validate);
        }

        log.debug("No refresh token found in cookie, header, or body");
        return Optional.empty();
    }

    /* =====================
       COOKIE
       ===================== */

    private Optional<String> extractFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            log.debug("No cookies present in request");
            return Optional.empty();
        }

        return Arrays.stream(cookies)
                .filter(Objects::nonNull)
                .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                .map(Cookie::getValue)
                .filter(v -> {
                    boolean valid = v != null && !v.isBlank();
                    if (!valid) {
                        log.debug("Refresh token cookie present but empty");
                    }
                    return valid;
                })
                .findFirst();
    }

    /* =====================
       HEADER
       ===================== */

    private Optional<String> extractFromHeader(HttpServletRequest request) {
        String value = request.getHeader(REFRESH_HEADER);

        if (value == null) {
            log.debug("Refresh token header '{}' not present", REFRESH_HEADER);
            return Optional.empty();
        }

        if (value.isBlank()) {
            log.debug("Refresh token header '{}' is blank", REFRESH_HEADER);
            return Optional.empty();
        }

        return Optional.of(value.trim());
    }

    /* =====================
       BODY (JSON)
       ===================== */

    private Optional<String> extractFromBody(HttpServletRequest request) {
        if (!(request instanceof ContentCachingRequestWrapper wrapper)) {
            log.debug("Request is not ContentCachingRequestWrapper; body not readable");
            return Optional.empty();
        }

        byte[] body = wrapper.getContentAsByteArray();
        if (body.length == 0) {
            log.debug("Request body is empty");
            return Optional.empty();
        }

        try {
            JsonNode root = objectMapper.readTree(body);
            JsonNode tokenNode = root.get(REFRESH_BODY_FIELD);

            if (tokenNode == null) {
                log.debug("Request body does not contain '{}' field", REFRESH_BODY_FIELD);
                return Optional.empty();
            }

            String token = tokenNode.asText();

            if (token.isBlank()) {
                log.debug("Refresh token field '{}' is blank", REFRESH_BODY_FIELD);
                throw new MissingRefreshTokenException();
            }

            return Optional.of(token.trim());

        } catch (MissingRefreshTokenException ex) {
            throw ex;

        } catch (Exception ex) {
            log.warn("Failed to parse refresh token from request body (invalid JSON)");
            throw new InvalidRefreshTokenException("Malformed refresh token payload");
        }
    }

    /* =====================
       VALIDATION
       ===================== */

    private String validate(String token) {
        log.debug("Validating refresh token (length={})", token.length());

        if (token.isBlank()) {
            log.debug("Refresh token validation failed: token is blank");
            throw new MissingRefreshTokenException();
        }

        if (token.length() > MAX_TOKEN_LENGTH) {
            log.warn("Refresh token validation failed: token length exceeds {}", MAX_TOKEN_LENGTH);
            throw new InvalidRefreshTokenException("Refresh token too long");
        }

        if (!token.matches("^[A-Za-z0-9._~-]+$")) {
            log.warn("Refresh token validation failed: token contains invalid characters");
            throw new InvalidRefreshTokenException("Refresh token has invalid characters");
        }

        log.debug("Refresh token validation successful");
        return token;
    }
}
