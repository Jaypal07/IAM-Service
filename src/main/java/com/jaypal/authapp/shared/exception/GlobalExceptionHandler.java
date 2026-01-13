package com.jaypal.authapp.shared.exception;

import com.jaypal.authapp.auth.exception.*;
import com.jaypal.authapp.token.exception.*;
import com.jaypal.authapp.user.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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
        final String correlationId = resolveCorrelationId(request);
        final String path = extractPath(request);

        if (serverError) {
            log.error("{} | correlationId={} | path={}", logMessage, correlationId, path);
        } else {
            log.warn("{} | correlationId={} | path={}", logMessage, correlationId, path);
        }

        final Map<String, Object> body = new HashMap<>();
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
                "You do not have permission to access this resource.",
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
                "The email or password you entered is incorrect.",
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
                "Authentication state is no longer valid. Please log in again.",
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
                "Your account has been disabled. Please contact support.",
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
                "Please verify your email address before logging in.",
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
                "Your account is locked. Please contact support.",
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
                ex.getMessage(),
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
                "This email address is already verified.",
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
                ex.getMessage(),
                request,
                "Email verification failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    @ExceptionHandler(EmailNotRegisteredException.class)
    public ResponseEntity<Void> swallowEmailNotRegistered() {
        log.debug("Email verification resend for non-existent email");
        return ResponseEntity.ok().build();
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
                ex.getMessage(),
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
                "Your session has expired. Please log in again.",
                request,
                "Refresh token failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    /* =====================
       GENERIC / INFRA
       ===================== */

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleResourceNotFound(
            ResourceNotFoundException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.NOT_FOUND,
                "Resource not found",
                ex.getMessage(),
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
        final Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        final Map<String, Object> body = new HashMap<>();
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
        final Throwable cause = ex.getCause();
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
                "Request violates data constraints.",
                request,
                "Data integrity violation",
                true
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
                "The requested resource was not found.",
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
        return problem(
                HttpStatus.BAD_REQUEST,
                "Invalid request body",
                "Malformed JSON or invalid field types.",
                request,
                "Request body deserialization failed",
                false
        );
    }



    @ExceptionHandler(InternalAuthenticationServiceException.class)
    public ResponseEntity<Map<String, Object>> handleInternalAuthenticationServiceException(
            InternalAuthenticationServiceException ex,
            WebRequest request
    ) {
        Throwable cause = ex.getCause();

        // ---- ACCOUNT DISABLED ----
        if (cause instanceof DisabledException ||
                cause instanceof UserAccountDisabledException) {

            return problem(
                    HttpStatus.FORBIDDEN,
                    "Account disabled",
                    "Your account has been disabled. Please contact support or verify you email",
                    request,
                    "Authentication failure: account disabled (wrapped)",
                    false
            );
        }

        // ---- ACCOUNT LOCKED ----
        if (cause instanceof LockedException) {
            return problem(
                    HttpStatus.FORBIDDEN,
                    "Account locked",
                    "Your account is locked. Please contact support.",
                    request,
                    "Authentication failure: account locked (wrapped)",
                    false
            );
        }

        // ---- INVALID CREDENTIALS ----
        if (cause instanceof BadCredentialsException) {
            return problem(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid credentials",
                    "The email or password you entered is incorrect.",
                    request,
                    "Authentication failure: invalid credentials (wrapped)",
                    false
            );
        }

        // ---- FALLBACK ----
        log.error(
                "Unhandled InternalAuthenticationServiceException cause: {}",
                cause != null ? cause.getClass().getName() : "null",
                ex
        );

        return problem(
                HttpStatus.UNAUTHORIZED,
                "Authentication failed",
                "Authentication failed. Please try again.",
                request,
                "Authentication failure: internal service exception",
                true
        );
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
