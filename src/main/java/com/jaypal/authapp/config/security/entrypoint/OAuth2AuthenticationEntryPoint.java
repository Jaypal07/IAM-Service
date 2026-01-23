package com.jaypal.authapp.config.security.entrypoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) {
        log.warn(
                "OAuth authentication entry point triggered for: {} - Reason: {}",
                request.getRequestURI(),
                exception.getMessage()
        );

        try {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");

            Map<String, Object> errorBody = Map.of(
                    "timestamp", Instant.now().toString(),
                    "status", HttpStatus.UNAUTHORIZED.value(),
                    "error", HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                    "message", "OAuth2 authentication required",
                    "path", request.getRequestURI()
            );

            response.getWriter().write(objectMapper.writeValueAsString(errorBody));
            response.getWriter().flush();

        } catch (IOException ex) {
            log.error(
                    "Failed to write OAuth unauthorized response for path: {}",
                    request.getRequestURI(),
                    ex
            );
        }
    }
}
