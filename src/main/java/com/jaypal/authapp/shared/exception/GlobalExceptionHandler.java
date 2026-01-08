package com.jaypal.authapp.shared.exception;

import com.jaypal.authapp.auth.exception.*;
import com.jaypal.authapp.token.exception.*;
import com.jaypal.authapp.user.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";

    // ---------------------------------------------------------
    // RFC 7807 RESPONSE BUILDER
    // ---------------------------------------------------------

    private ResponseEntity<Map<String, Object>> problem(
            HttpStatus status,
            String title,
            String detail,
            WebRequest request,
            String logMessage,
            Throwable ex,
            boolean logStackTrace
    ) {
        String correlationId = UUID.randomUUID().toString();
        String path = extractPath(request);

        if (logStackTrace) {
            log.error("{} | correlationId={}", logMessage, correlationId, ex);
        } else {
            log.warn("{} | correlationId={}", logMessage, correlationId);
        }

        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create("about:blank"));
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

    private String extractPath(WebRequest request) {
        if (request instanceof ServletWebRequest servletRequest) {
            return servletRequest.getRequest().getRequestURI();
        }
        return "N/A";
    }

    // ---------------------------------------------------------
    // AUTHENTICATION
    // ---------------------------------------------------------

    @ExceptionHandler({
            BadCredentialsException.class,
            InvalidCredentialsException.class,
            UsernameNotFoundException.class
    })
    public ResponseEntity<Map<String, Object>> handleInvalidCredentials(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Authentication failed",
                "Invalid username or password.",
                request,
                "Authentication failure: invalid credentials",
                ex,
                false
        );
    }

    @ExceptionHandler({
            DisabledException.class,
            UserAccountDisabledException.class
    })
    public ResponseEntity<Map<String, Object>> handleAccountDisabled(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Account disabled",
                "Please verify your email address before logging in.",
                request,
                "Authentication failure: account disabled",
                ex,
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
                ex,
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
                "Authenticated user missing",
                ex,
                true
        );
    }

    // ---------------------------------------------------------
    // AUTHORIZATION
    // ---------------------------------------------------------

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
                "Authorization failure",
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // EMAIL / VERIFICATION
    // ---------------------------------------------------------

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
                "Duplicate email",
                ex,
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
                "Account already verified",
                "This email address is already verified.",
                request,
                "Account already verified",
                ex,
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
                "Email verification failure",
                ex,
                false
        );
    }

    @ExceptionHandler(EmailNotRegisteredException.class)
    public ResponseEntity<Void> swallowEmailNotRegistered() {
        return ResponseEntity.noContent().build();
    }

    // ---------------------------------------------------------
    // PASSWORD RESET
    // ---------------------------------------------------------

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
                "Password operation failure",
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // REFRESH TOKEN
    // ---------------------------------------------------------

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
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // VALIDATION
    // ---------------------------------------------------------

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(
            MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        return problem(
                HttpStatus.BAD_REQUEST,
                "Validation failed",
                errors.toString(),
                request,
                "Validation failure",
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // DATA INTEGRITY
    // ---------------------------------------------------------

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrity(
            DataIntegrityViolationException ex,
            WebRequest request
    ) {
        Throwable cause = ex.getCause();
        if (cause instanceof org.hibernate.exception.ConstraintViolationException cve) {
            if ("users_email".equalsIgnoreCase(cve.getConstraintName())) {
                return problem(
                        HttpStatus.CONFLICT,
                        "Email already exists",
                        "An account with this email address already exists.",
                        request,
                        "Duplicate email constraint violation",
                        ex,
                        false
                );
            }
        }

        return problem(
                HttpStatus.BAD_REQUEST,
                "Invalid request",
                "Request violates data constraints.",
                request,
                "Unhandled data integrity violation",
                ex,
                false
        );
    }

    // ---------------------------------------------------------
    // FALLBACK
    // ---------------------------------------------------------

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal server error",
                "An unexpected error occurred.",
                request,
                "Unhandled exception",
                ex,
                true
        );
    }
}
