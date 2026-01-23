package com.jaypal.authapp.exception.handler;

import com.jaypal.authapp.domain.user.exception.UserAccountDisabledException;
import com.jaypal.authapp.exception.auth.AuthenticatedUserMissingException;
import com.jaypal.authapp.exception.auth.EmailNotVerifiedException;
import com.jaypal.authapp.exception.response.ApiErrorResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationExceptionHandler {

    private final ApiErrorResponseBuilder problemBuilder;

    public ResponseEntity<Map<String, Object>> handleBadCredentials(
            BadCredentialsException ex,
            WebRequest request
    ) {
        return buildResponse(
                HttpStatus.UNAUTHORIZED,
                "Invalid credentials",
                ex,
                "The email or password you entered is incorrect.",
                request,
                "Authentication failure: invalid credentials",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleAuthenticatedUserMissing(
            AuthenticatedUserMissingException ex,
            WebRequest request
    ) {
        return buildResponse(
                HttpStatus.UNAUTHORIZED,
                "Authentication context invalid",
                ex,
                "Authentication state is no longer valid. Please log in again.",
                request,
                "Authenticated user missing from database",
                true
        );
    }

    public ResponseEntity<Map<String, Object>> handleAccountDisabled(
            UserAccountDisabledException ex,
            WebRequest request
    ) {
        return buildResponse(
                HttpStatus.FORBIDDEN,
                "Account disabled",
                ex,
                "Your account has been disabled. Please contact support.",
                request,
                "Account disabled",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleEmailNotVerified(
            EmailNotVerifiedException ex,
            WebRequest request
    ) {
        return buildResponse(
                HttpStatus.FORBIDDEN,
                "Email not verified",
                ex,
                "Please verify your email address before logging in.",
                request,
                "Authentication failure: email not verified",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            LockedException ex,
            WebRequest request
    ) {
        return buildResponse(
                HttpStatus.FORBIDDEN,
                "Account locked",
                ex,
                "Your account is locked. Please contact support.",
                request,
                "Authentication failure: account locked",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleInternalAuthenticationServiceException(
            InternalAuthenticationServiceException ex,
            WebRequest request
    ) {
        Throwable cause = ex.getCause();

        if (isAccountDisabled(cause)) {
            return handleWrapped(
                    cause,
                    HttpStatus.FORBIDDEN,
                    "Account disabled",
                    "Your account has been disabled. Please contact support.",
                    request,
                    "Authentication failure: account disabled (wrapped)"
            );
        }

        if (cause instanceof LockedException) {
            return handleWrapped(
                    cause,
                    HttpStatus.FORBIDDEN,
                    "Account locked",
                    "Your account is locked. Please contact support.",
                    request,
                    "Authentication failure: account locked (wrapped)"
            );
        }

        if (cause instanceof EmailNotVerifiedException) {
            return handleWrapped(
                    cause,
                    HttpStatus.FORBIDDEN,
                    "Email not verified",
                    "Please verify your email address before logging in.",
                    request,
                    "Authentication failure: email not verified (wrapped)"
            );
        }

        if (cause instanceof BadCredentialsException) {
            return handleWrapped(
                    cause,
                    HttpStatus.UNAUTHORIZED,
                    "Invalid credentials",
                    "The email or password you entered is incorrect.",
                    request,
                    "Authentication failure: invalid credentials (wrapped)"
            );
        }

        log.error("Unhandled InternalAuthenticationServiceException", ex);

        return buildResponse(
                HttpStatus.UNAUTHORIZED,
                "Authentication failed",
                ex,
                "Authentication failed. Please try again.",
                request,
                "Authentication failure: internal service exception",
                true
        );
    }

    private boolean isAccountDisabled(Throwable cause) {
        return cause instanceof DisabledException;
    }

    private ResponseEntity<Map<String, Object>> handleWrapped(
            Throwable cause,
            HttpStatus status,
            String title,
            String defaultMessage,
            WebRequest request,
            String logMessage
    ) {
        return buildResponse(
                status,
                title,
                cause,
                defaultMessage,
                request,
                logMessage,
                false
        );
    }

    private ResponseEntity<Map<String, Object>> buildResponse(
            HttpStatus status,
            String title,
            Throwable ex,
            String defaultMessage,
            WebRequest request,
            String logMessage,
            boolean includeStackTrace
    ) {
        return problemBuilder.build(
                status,
                title,
                problemBuilder.resolveMessage(ex, defaultMessage),
                request,
                logMessage,
                includeStackTrace
        );
    }
}
