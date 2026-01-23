package com.jaypal.authapp.config.security.entrypoint;

import com.jaypal.authapp.exception.handler.AuthenticationExceptionHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class SecurityAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final AuthenticationExceptionHandler authenticationExceptionHandler;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException {

        ResponseEntity<Map<String, Object>> entity =
                authenticationExceptionHandler.handleInternalAuthenticationServiceException(
                        wrap(exception),
                        new ServletWebRequest(request)
                );

        writeResponse(response, entity);
    }

    private InternalAuthenticationServiceException wrap(AuthenticationException ex) {
        return ex instanceof InternalAuthenticationServiceException internal
                ? internal
                : new InternalAuthenticationServiceException(ex.getMessage(), ex);
    }

    private void writeResponse(
            HttpServletResponse response,
            ResponseEntity<Map<String, Object>> entity
    ) throws IOException {

        response.setStatus(entity.getStatusCode().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        response.getWriter().write(
                new com.fasterxml.jackson.databind.ObjectMapper()
                        .writeValueAsString(entity.getBody())
        );
        response.getWriter().flush();
    }
}
