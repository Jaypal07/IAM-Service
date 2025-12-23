package com.jaypal.authapp.exception;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.model.AuthAuditEvent;
import com.jaypal.authapp.audit.service.AuthAuditService;
import com.jaypal.authapp.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import javax.security.auth.login.CredentialException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    // ---------------------------------------------------------
    // COMMON UTILITIES
    // ---------------------------------------------------------

    private final AuthAuditService authAuditService;

    private String extractPath(WebRequest request) {
        if (request instanceof ServletWebRequest servletRequest) {
            return servletRequest.getRequest().getRequestURI();
        }
        return "N/A";
    }

    private ResponseEntity<ErrorResponse> buildErrorResponse(
            Exception ex,
            HttpStatus status,
            String path
    ) {
        ErrorResponse errorResponse = new ErrorResponse(
                path,
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage()
        );

        return ResponseEntity.status(status).body(errorResponse);
    }

    // ---------------------------------------------------------
    // AUTHENTICATION EXCEPTIONS
    // ---------------------------------------------------------

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
            BadCredentialsException ex,
            HttpServletRequest request
    ) {

        authAuditService.log(
                null,
                AuthAuditEvent.LOGIN_FAILURE,
                "LOCAL",
                request,
                false,
                "Invalid username or password"
        );

        return buildErrorResponse(
                ex,
                HttpStatus.UNAUTHORIZED,
                request.getRequestURI()
        );
    }


    @ExceptionHandler({
            UsernameNotFoundException.class,
            DisabledException.class,
            CredentialException.class
    })
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            Exception ex, HttpServletRequest request
    ) {
        log.warn("Authentication error at {}: {}", request.getRequestURI(), ex.getMessage());

        return buildErrorResponse(
                ex,
                HttpStatus.UNAUTHORIZED,
                request.getRequestURI()
        );
    }

    // ---------------------------------------------------------
    // RESOURCE NOT FOUND
    // ---------------------------------------------------------
    @ExceptionHandler(ResourceNotFoundExceptions.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(
            ResourceNotFoundExceptions ex, WebRequest request
    ) {
        String path = extractPath(request);

        log.warn("Resource not found at {}: {}", path, ex.getMessage());

        return buildErrorResponse(
                ex,
                HttpStatus.NOT_FOUND,
                path
        );
    }

    // ---------------------------------------------------------
    // VALIDATION ERRORS (DTO/RequestBody)
    // ---------------------------------------------------------
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> handleValidationExceptions(
            MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        String path = extractPath(request);

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String field = ((FieldError) error).getField();
            String message = error.getDefaultMessage();
            errors.put(field, message);
        });

        log.warn("Validation error at {}: {}", path, errors);

        ErrorResponse errorResponse = new ErrorResponse(
                path,
                HttpStatus.BAD_REQUEST.value(),
                "Validation Failed",
                errors.toString()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    // ---------------------------------------------------------
    // BAD REQUEST
    // ---------------------------------------------------------
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex, WebRequest request
    ) {
        String path = extractPath(request);
        log.warn("Illegal argument at {}: {}", path, ex.getMessage());

        return buildErrorResponse(
                ex,
                HttpStatus.BAD_REQUEST,
                path
        );
    }

    // ---------------------------------------------------------
    // FALLBACK — Global Exception Handler
    // ---------------------------------------------------------
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(
            Exception ex, WebRequest request
    ) {
        String path = extractPath(request);

        // Log full stack trace for internal debugging
        log.error("Unexpected error at {}: {}", path, ex.toString(), ex);

        ErrorResponse errorResponse = new ErrorResponse(
                path,
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "An unexpected error occurred. Please try again later."
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
}
