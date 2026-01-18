package com.jaypal.authapp.exception;

import com.jaypal.authapp.domain.token.exception.*;
import com.jaypal.authapp.domain.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.domain.user.exception.InvalidRoleOperationException;
import com.jaypal.authapp.domain.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.domain.user.exception.UserAccountDisabledException;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RateLimitExceededException;
import com.jaypal.authapp.exception.auth.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.net.URI;
import java.time.Instant;
import java.util.*;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";
    private static final String TYPE_ABOUT_BLANK = "about:blank";

    /* =====================
       CORE PROBLEM RESPONSE
       ===================== */

    private ResponseEntity<Map<String, Object>> problem(
            HttpStatus status,
            String title,
            String detail,
            WebRequest request,
            String logMessage,
            boolean serverError
    ) {
        String correlationId = resolveCorrelationId(request);
        String path = extractPath(request);

        if (serverError) {
            log.error("{} | correlationId={} | path={}", logMessage, correlationId, path);
        } else {
            log.warn("{} | correlationId={} | path={}", logMessage, correlationId, path);
        }

        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", title);
        body.put("status", status.value());
        body.put("detail", detail);
        body.put("instance", path);
        body.put("correlationId", correlationId);
        body.put("timestamp", Instant.now().toString());

        return ResponseEntity
                .status(status)
                .header(CORRELATION_HEADER, correlationId)
                .body(body);
    }

    /* =====================
       AUTHORIZATION
       ===================== */

    @ExceptionHandler({
            AccessDeniedException.class,
            AuthorizationDeniedException.class
    })
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Access denied",
                resolveMessage(ex, "You do not have permission to access this resource."),
                request,
                "Authorization failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    /* =====================
       ACCOUNT / AUTH DOMAIN
       ===================== */

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(
            BadCredentialsException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Invalid credentials",
                resolveMessage(ex, "The email or password you entered is incorrect."),
                request,
                "Authentication failure: invalid credentials",
                false
        );
    }

    @ExceptionHandler(AuthenticatedUserMissingException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticatedUserMissing(
            AuthenticatedUserMissingException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Authentication context invalid",
                resolveMessage(ex, "Authentication state is no longer valid. Please log in again."),
                request,
                "Authenticated user missing from database",
                true
        );
    }

    @ExceptionHandler(UserAccountDisabledException.class)
    public ResponseEntity<Map<String, Object>> handleAccountDisabled(
            UserAccountDisabledException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Account disabled",
                resolveMessage(ex, "Your account has been disabled. Please contact support."),
                request,
                "Account disabled",
                false
        );
    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleEmailNotVerified(
            EmailNotVerifiedException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Email not verified",
                resolveMessage(ex, "Please verify your email address before logging in."),
                request,
                "Authentication failure: email not verified",
                false
        );
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            LockedException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Account locked",
                resolveMessage(ex, "Your account is locked. Please contact support."),
                request,
                "Authentication failure: account locked",
                false
        );
    }

    /* =====================
       REGISTRATION / EMAIL
       ===================== */

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.CONFLICT,
                "Email already exists",
                resolveMessage(ex, "An account with this email already exists."),
                request,
                "Duplicate email registration attempt",
                false
        );
    }

    @ExceptionHandler(EmailAlreadyVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleAlreadyVerified(
            EmailAlreadyVerifiedException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.CONFLICT,
                "Email already verified",
                resolveMessage(ex, "This email address is already verified."),
                request,
                "Email verification for already-verified account",
                false
        );
    }

    @ExceptionHandler({
            VerificationTokenExpiredException.class,
            VerificationTokenInvalidException.class
    })
    public ResponseEntity<Map<String, Object>> handleVerificationTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Verification failed",
                resolveMessage(ex, "Verification token is invalid or expired."),
                request,
                "Email verification failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    @ExceptionHandler(EmailNotRegisteredException.class)
    public ResponseEntity<Void> swallowEmailNotRegistered() {
        log.debug("Email verification resend call for non-existent email");
        return ResponseEntity.ok().build();
    }

    @ExceptionHandler(SilentEmailVerificationResendException.class)
    public ResponseEntity<Void> handleSilentVerificationResend(
            SilentEmailVerificationResendException ex,
            WebRequest request
    ) {
        log.debug(
                "Silent verification resend | path={} | reason={}",
                extractPath(request),
                ex.getMessage()
        );

        // Enumeration-safe response
        return ResponseEntity.ok().build();
    }

    @ExceptionHandler(EmailDeliveryFailedException.class)
    public ResponseEntity<Map<String, Object>> handleEmailDeliveryFailed(
            EmailDeliveryFailedException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Email delivery failed",
                "We were unable to send the verification email. Please try again later.",
                request,
                "Email delivery failure",
                true
        );
    }



    /* =====================
   USER / ROLE DOMAIN
   ===================== */

    @ExceptionHandler(InvalidRoleOperationException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidRoleOperation(
            InvalidRoleOperationException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.CONFLICT,
                "Invalid role operation",
                resolveMessage(ex, "Invalid role operation."),
                request,
                "Invalid role operation attempted",
                false
        );
    }


    /* =====================
       PASSWORD / TOKENS
       ===================== */

    @ExceptionHandler({
            PasswordPolicyViolationException.class,
            PasswordResetTokenInvalidException.class,
            PasswordResetTokenExpiredException.class
    })
    public ResponseEntity<Map<String, Object>> handlePasswordFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Password operation failed",
                resolveMessage(ex, "Password operation failed."),
                request,
                "Password operation failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    @ExceptionHandler({
            RefreshTokenExpiredException.class,
            RefreshTokenNotFoundException.class,
            RefreshTokenRevokedException.class,
            RefreshTokenUserMismatchException.class,
            RefreshTokenException.class,
            InvalidRefreshTokenException.class,
            MissingRefreshTokenException.class
    })
    public ResponseEntity<Map<String, Object>> handleRefreshTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Invalid refresh token",
                resolveMessage(ex, "Your session has expired. Please log in again."),
                request,
                "Refresh token failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    /* =====================
       GENERIC / INFRA
       ===================== */


    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<Map<String, Object>> handleHandlerMethodValidation(
            HandlerMethodValidationException ex,
            WebRequest request
    ) {
        Map<String, String> errors = new HashMap<>();

        ex.getParameterValidationResults().forEach(result -> {
            String paramName = result.getMethodParameter().getParameterName();

            result.getResolvableErrors().forEach(error -> {
                errors.put(paramName, error.getDefaultMessage());
            });
        });

        log.warn(
                "Handler method validation failed | path={} | violations={}",
                extractPath(request),
                errors.size()
        );

        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", "Validation failed");
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("detail", "Request validation failed");
        body.put("errors", errors);
        body.put("instance", extractPath(request));
        body.put("timestamp", Instant.now().toString());

        return ResponseEntity
                .badRequest()
                .header(CORRELATION_HEADER, resolveCorrelationId(request))
                .body(body);
    }


    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleMethodArgumentTypeMismatch(
            MethodArgumentTypeMismatchException ex,
            WebRequest request
    ) {
        String parameterName = ex.getName();
        Object value = ex.getValue();
        Class<?> requiredType = ex.getRequiredType();

        String detail = (requiredType != null)
                ? "Parameter '%s' must be of type '%s'."
                .formatted(parameterName, requiredType.getSimpleName())
                : "Invalid value for parameter '%s'.".formatted(parameterName);

        if (value != null) {
            detail += " Provided value: '%s'.".formatted(value);
        }

        return problem(
                HttpStatus.BAD_REQUEST,
                "Invalid request parameter",
                detail,
                request,
                "Method argument type mismatch: " + parameterName,
                false
        );
    }


    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleResourceNotFound(
            ResourceNotFoundException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.NOT_FOUND,
                "Resource not found",
                resolveMessage(ex, "The requested resource was not found."),
                request,
                "Resource not found",
                false
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(
            MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", "Validation failed");
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("detail", "Request validation failed");
        body.put("errors", errors);
        body.put("instance", extractPath(request));
        body.put("timestamp", Instant.now().toString());

        log.warn("Validation failure | path={} | errors={}", extractPath(request), errors.size());
        return ResponseEntity.badRequest().body(body);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrity(
            DataIntegrityViolationException ex,
            WebRequest request
    ) {
        Throwable cause = ex.getCause();
        if (cause instanceof org.hibernate.exception.ConstraintViolationException cve &&
                cve.getConstraintName() != null &&
                cve.getConstraintName().toLowerCase().contains("email")) {

            return problem(
                    HttpStatus.CONFLICT,
                    "Email already exists",
                    "An account with this email address already exists.",
                    request,
                    "Duplicate email constraint violation",
                    false
            );
        }

        return problem(
                HttpStatus.BAD_REQUEST,
                "Invalid request",
                resolveMessage(ex, "Request violates data constraints."),
                request,
                "Data integrity violation",
                true
        );
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleRateLimit(
            RateLimitExceededException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.TOO_MANY_REQUESTS,
                "Too many requests",
                resolveMessage(ex, "Too many requests. Please try again later."),
                request,
                "Rate limit exceeded",
                false
        );
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoResource(
            NoResourceFoundException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.NOT_FOUND,
                "Resource not found",
                resolveMessage(ex, "The requested resource was not found."),
                request,
                "404 Not Found",
                false
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleNotReadable(
            HttpMessageNotReadableException ex,
            WebRequest request
    ) {
        String message = ex.getMessage();

        // ✅ Explicit handling for missing request body
        if (message != null && message.contains("Required request body is missing")) {
            return problem(
                    HttpStatus.BAD_REQUEST,
                    "Invalid request body",
                    "Required request body is missing",
                    request,
                    "Required request body is missing",
                    false
            );
        }

        // Fallback → malformed JSON, invalid types, etc.
        return problem(
                HttpStatus.BAD_REQUEST,
                "Invalid request body",
                "Malformed JSON or invalid field types.",
                request,
                "Request body deserialization failed",
                false
        );
    }


    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> handleMissingRequestParam(
            MissingServletRequestParameterException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Missing request parameter",
                resolveMessage(
                        ex,
                        "Required request parameter '%s' is missing."
                                .formatted(ex.getParameterName())
                ),
                request,
                "Missing request parameter: " + ex.getParameterName(),
                false
        );
    }

    @ExceptionHandler(InternalAuthenticationServiceException.class)
    public ResponseEntity<Map<String, Object>> handleInternalAuthenticationServiceException(
            InternalAuthenticationServiceException ex,
            WebRequest request
    ) {
        Throwable cause = ex.getCause();

        if (cause instanceof DisabledException || cause instanceof UserAccountDisabledException) {
            return problem(
                    HttpStatus.FORBIDDEN,
                    "Account disabled",
                    resolveMessage(cause, "Your account has been disabled. Please contact support."),
                    request,
                    "Authentication failure: account disabled (wrapped)",
                    false
            );
        }

        if (cause instanceof LockedException) {
            return problem(
                    HttpStatus.FORBIDDEN,
                    "Account locked",
                    resolveMessage(cause, "Your account is locked. Please contact support."),
                    request,
                    "Authentication failure: account locked (wrapped)",
                    false
            );
        }

        if (cause instanceof BadCredentialsException) {
            return problem(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid credentials",
                    resolveMessage(cause, "The email or password you entered is incorrect."),
                    request,
                    "Authentication failure: invalid credentials (wrapped)",
                    false
            );
        }

        log.error("Unhandled InternalAuthenticationServiceException", ex);

        return problem(
                HttpStatus.UNAUTHORIZED,
                "Authentication failed",
                resolveMessage(ex, "Authentication failed. Please try again."),
                request,
                "Authentication failure: internal service exception",
                true
        );
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(
            IllegalArgumentException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Invalid request",
                resolveMessage(ex, "Invalid request."),
                request,
                "Client error: illegal argument",
                false
        );
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ProblemDetail> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex,
            WebRequest request
    ) {
        Set<HttpMethod> supported = ex.getSupportedHttpMethods();

        String supportedMethods = (supported == null || supported.isEmpty())
                ? "N/A"
                : String.join(", ", supported.stream().map(HttpMethod::name).toList());

        String correlationId = resolveCorrelationId(request);
        String path = extractPath(request);

        log.warn(
                "Method not supported | {} → {} | path={} | correlationId={}",
                ex.getMethod(),
                supportedMethods,
                path,
                correlationId
        );

        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.METHOD_NOT_ALLOWED);
        problem.setType(URI.create(TYPE_ABOUT_BLANK));
        problem.setTitle("Method not allowed");
        problem.setDetail(
                "HTTP method '%s' is not supported. Supported methods: %s."
                        .formatted(ex.getMethod(), supportedMethods)
        );
        problem.setInstance(URI.create(path));
        problem.setProperty("correlationId", correlationId);
        problem.setProperty("timestamp", Instant.now().toString());

        HttpHeaders headers = new HttpHeaders();
        headers.add(CORRELATION_HEADER, correlationId);
        if (supported != null && !supported.isEmpty()) {
            headers.setAllow(supported);
        }

        return new ResponseEntity<>(problem, headers, HttpStatus.METHOD_NOT_ALLOWED);
    }

    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(
            jakarta.validation.ConstraintViolationException ex,
            WebRequest request
    ) {
        Map<String, String> errors = new HashMap<>();
        ex.getConstraintViolations().forEach(v ->
                errors.put(
                        v.getPropertyPath() != null ? v.getPropertyPath().toString() : "parameter",
                        v.getMessage()
                )
        );

        log.warn("Constraint violation | path={} | violations={}",
                extractPath(request), errors.size());

        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", "Validation failed");
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("detail", "Request validation failed");
        body.put("errors", errors);
        body.put("instance", extractPath(request));
        body.put("timestamp", Instant.now().toString());

        return ResponseEntity
                .badRequest()
                .header(CORRELATION_HEADER, resolveCorrelationId(request))
                .body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal server error",
                "An unexpected error occurred. Please contact support if the problem persists.",
                request,
                "Unhandled exception: " + ex.getClass().getSimpleName(),
                true
        );
    }

    /* =====================
       HELPERS
       ===================== */

    private String resolveMessage(Throwable ex, String defaultMessage) {
        return (ex != null && ex.getMessage() != null && !ex.getMessage().isBlank())
                ? ex.getMessage()
                : defaultMessage;
    }

    private String extractPath(WebRequest request) {
        if (request instanceof ServletWebRequest servletRequest) {
            return servletRequest.getRequest().getRequestURI();
        }
        return "N/A";
    }

    private String resolveCorrelationId(WebRequest request) {
        if (request instanceof ServletWebRequest swr) {
            String existing = swr.getRequest().getHeader(CORRELATION_HEADER);
            if (existing != null && !existing.isBlank()) {
                return existing;
            }
        }
        return UUID.randomUUID().toString();
    }
}
