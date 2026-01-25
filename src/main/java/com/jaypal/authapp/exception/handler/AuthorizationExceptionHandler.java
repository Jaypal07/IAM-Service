package com.jaypal.authapp.exception.handler;

import com.jaypal.authapp.exception.authorizationAudit.AuditLogger;
import com.jaypal.authapp.exception.response.ApiErrorResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthorizationExceptionHandler {

    private final ApiErrorResponseBuilder problemBuilder;

    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            Exception ex,
            WebRequest request,
            AuditLogger auditLogger
    ) {
        auditLogger.logAccessDenied(ex, request);

        return problemBuilder.build(
                HttpStatus.FORBIDDEN,
                "Access denied",
                problemBuilder.resolveMessage(ex, "You do not have permission to access this resource."),
                request,
                "Authorization failure: " + ex.getClass().getSimpleName(),
                false
        );
    }
}