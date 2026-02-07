package com.jaypal.authapp.exception.handler;

import com.jaypal.authapp.exception.response.ApiErrorResponseBuilder;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitExceededException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.stereotype.Component;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class InfrastructureExceptionHandler {

        private static final String CORRELATION_HEADER = "X-Correlation-Id";
        private static final String TYPE_ABOUT_BLANK = "about:blank";

        private final ApiErrorResponseBuilder problemBuilder;

        public ResponseEntity<Map<String, Object>> handleDataIntegrity(
                        DataIntegrityViolationException ex,
            WebRequest request
    ) {
                if (isEmailConstraintViolation(ex)) {
                        return createDuplicateEmailResponse(request);
                }

                return problemBuilder.build(
                                HttpStatus.BAD_REQUEST,
                                "Invalid request",
                                problemBuilder.resolveMessage(ex, "Request violates data constraints."),
                                request,
                                "Data integrity violation",
                true
        );
        }

        public ResponseEntity<Map<String, Object>> handleRateLimit(
                        RateLimitExceededException ex,
            WebRequest request
    ) {
                return problemBuilder.build(
                                HttpStatus.TOO_MANY_REQUESTS,
                                "Too many requests",
                                problemBuilder.resolveMessage(ex, "Too many requests. Please try again later."),
                                request,
                                "Rate limit exceeded",
                                false);
        }

        public ResponseEntity<Map<String, Object>> handleNoResource(
                        NoResourceFoundException ex,
                        WebRequest request) {
                return problemBuilder.build(
                                HttpStatus.NOT_FOUND,
                                "Resource not found",
                                problemBuilder.resolveMessage(ex, "The requested resource was not found."),
                                request,
                                "404 Not Found",
                                false);
        }

        public ResponseEntity<Map<String, Object>> handleHttpMessageNotReadable(
                        HttpMessageNotReadableException ex,
                        WebRequest request) {
                String message = ex.getMessage();

                if (isMissingRequestBody(message)) {
                        return createMissingBodyResponse(request);
                }

                return createMalformedBodyResponse(request);
        }

        public ResponseEntity<Map<String, Object>> handleMissingRequestParameter(
                        MissingServletRequestParameterException ex,
                        WebRequest request) {
                return problemBuilder.build(
                                HttpStatus.BAD_REQUEST,
                                "Missing request parameter",
                                problemBuilder.resolveMessage(
                                                ex,
                                                "Required request parameter '%s' is missing."
                                                                .formatted(ex.getParameterName())),
                                request,
                                "Missing request parameter: " + ex.getParameterName(),
                                false);
        }

        public ResponseEntity<Map<String, Object>> handleIllegalArgument(
                        IllegalArgumentException ex,
                        WebRequest request) {
                return problemBuilder.build(
                                HttpStatus.BAD_REQUEST,
                                "Invalid request",
                                problemBuilder.resolveMessage(ex, "Invalid request."),
                                request,
                                "Client error: illegal argument",
                                false);
        }

        public ResponseEntity<ProblemDetail> handleMethodNotSupported(
                        HttpRequestMethodNotSupportedException ex,
                        WebRequest request) {
                Set<HttpMethod> supported = ex.getSupportedHttpMethods();
                String supportedMethods = formatSupportedMethods(supported);
                String correlationId = problemBuilder.resolveCorrelationId(request);
                String path = problemBuilder.extractPath(request);

                logMethodNotSupported(ex, supportedMethods, path, correlationId);

                ProblemDetail problem = createMethodNotSupportedProblem(
                                ex, supportedMethods, path, correlationId);

                HttpHeaders headers = createMethodNotSupportedHeaders(correlationId, supported);

                return new ResponseEntity<>(problem, headers, HttpStatus.METHOD_NOT_ALLOWED);
        }

        public ResponseEntity<Map<String, Object>> handleGenericException(
                        Exception ex,
                        WebRequest request) {
                // Log the full stack trace
                log.error("Unhandled exception occurred at path: " + request.getDescription(false), ex);

                return problemBuilder.build(
                                HttpStatus.INTERNAL_SERVER_ERROR,
                                "Internal server error",
                                "An unexpected error occurred. Please contact support if the problem persists.",
                                request,
                                "Unhandled exception: " + ex.getClass().getSimpleName(),
                                true);
        }

        // Private helper methods

        private boolean isEmailConstraintViolation(DataIntegrityViolationException ex) {
                Throwable cause = ex.getCause();
                return cause instanceof org.hibernate.exception.ConstraintViolationException cve &&
                                cve.getConstraintName() != null &&
                                cve.getConstraintName().toLowerCase().contains("email");
        }

        private ResponseEntity<Map<String, Object>> createDuplicateEmailResponse(WebRequest request) {
                return problemBuilder.build(
                                HttpStatus.CONFLICT,
                                "Email already exists",
                                "An account with this email address already exists.",
                                request,
                                "Duplicate email constraint violation",
                                false);
        }

        private boolean isMissingRequestBody(String message) {
                return message != null && message.contains("Required request body is missing");
        }

        private ResponseEntity<Map<String, Object>> createMissingBodyResponse(WebRequest request) {
                return problemBuilder.build(
                                HttpStatus.BAD_REQUEST,
                                "Invalid request body",
                                "Required request body is missing",
                                request,
                                "Required request body is missing",
                                false);
        }

        private ResponseEntity<Map<String, Object>> createMalformedBodyResponse(WebRequest request) {
                return problemBuilder.build(
                                HttpStatus.BAD_REQUEST,
                                "Invalid request body",
                                "Malformed JSON or invalid field types.",
                                request,
                                "Request body deserialization failed",
                                false);
        }

        private String formatSupportedMethods(Set<HttpMethod> supported) {
                return (supported == null || supported.isEmpty())
                                ? "N/A"
                                : String.join(", ", supported.stream().map(HttpMethod::name).toList());
        }

        private void logMethodNotSupported(
                        HttpRequestMethodNotSupportedException ex,
                        String supportedMethods,
                        String path,
                        String correlationId) {
                log.warn(
                                "Method not supported | {} → {} | path={} | correlationId={}",
                                ex.getMethod(),
                                supportedMethods,
                                path,
                                correlationId);
        }

        private ProblemDetail createMethodNotSupportedProblem(
                        HttpRequestMethodNotSupportedException ex,
                        String supportedMethods,
                        String path,
                        String correlationId) {
                ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.METHOD_NOT_ALLOWED);
                problem.setType(URI.create(TYPE_ABOUT_BLANK));
                problem.setTitle("Method not allowed");
                problem.setDetail(
                                "HTTP method '%s' is not supported. Supported methods: %s."
                                                .formatted(ex.getMethod(), supportedMethods));
                problem.setInstance(URI.create(path));
                problem.setProperty("correlationId", correlationId);
                problem.setProperty("timestamp", Instant.now().toString());
                return problem;
        }

        private HttpHeaders createMethodNotSupportedHeaders(
                        String correlationId,
                        Set<HttpMethod> supported) {
                HttpHeaders headers = new HttpHeaders();
                headers.add(CORRELATION_HEADER, correlationId);
                if (supported != null && !supported.isEmpty()) {
                        headers.setAllow(supported);
                }
                return headers;
        }
}