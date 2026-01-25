package com.jaypal.authapp.exception.response;

import com.jaypal.authapp.exception.authorizationAudit.RequestPathExtractor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

/**
 * Refactored ProblemResponseBuilder with improved separation of concerns.
 * Delegates specific responsibilities to focused components.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApiErrorResponseBuilder {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";

    private final CorrelationIdResolver correlationIdResolver;
    private final RequestPathExtractor requestPathExtractor;
    private final ErrorDetailFactory problemDetailFactory;
    private final ValidationErrorFactory validationErrorFactory;

    /**
     * Creates a standard problem response with correlation tracking.
     */
    public ResponseEntity<Map<String, Object>> build(
            HttpStatus status,
            String title,
            String detail,
            WebRequest request,
            String logMessage,
            boolean serverError
    ) {
        String correlationId = correlationIdResolver.resolve(request);
        String path = requestPathExtractor.extract(request);

        logError(serverError, logMessage, correlationId, path);

        Map<String, Object> body = problemDetailFactory.create(
                status, title, detail, path, correlationId
        );

        return ResponseEntity
                .status(status)
                .header(CORRELATION_HEADER, correlationId)
                .body(body);
    }

    /**
     * Creates a validation error response with field-level errors.
     */
    public ResponseEntity<Map<String, Object>> buildValidationError(
            Map<String, String> fieldErrors,
            WebRequest request
    ) {
        String correlationId = correlationIdResolver.resolve(request);
        String path = requestPathExtractor.extract(request);

        log.warn("Validation failure | path={} | errors={}", path, fieldErrors.size());

        Map<String, Object> body = validationErrorFactory.create(
                fieldErrors, path, correlationId
        );

        return ResponseEntity
                .badRequest()
                .header(CORRELATION_HEADER, correlationId)
                .body(body);
    }

    /**
     * Resolves a safe error message from an exception.
     */
    public String resolveMessage(Throwable ex, String defaultMessage) {
        return (ex != null && ex.getMessage() != null && !ex.getMessage().isBlank())
                ? ex.getMessage()
                : defaultMessage;
    }

    /**
     * Extracts the request path from the web request.
     */
    public String extractPath(WebRequest request) {
        return requestPathExtractor.extract(request);
    }

    /**
     * Resolves or generates a correlation ID for request tracking.
     */
    public String resolveCorrelationId(WebRequest request) {
        return correlationIdResolver.resolve(request);
    }

    /**
     * Logs the error appropriately based on severity.
     */
    private void logError(boolean serverError, String logMessage, String correlationId, String path) {
        if (serverError) {
            log.error("{} | correlationId={} | path={}", logMessage, correlationId, path);
        } else {
            log.warn("{} | correlationId={} | path={}", logMessage, correlationId, path);
        }
    }
}
