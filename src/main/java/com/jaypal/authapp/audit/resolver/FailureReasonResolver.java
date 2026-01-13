package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.domain.AuthFailureReason;
import com.jaypal.authapp.auth.exception.*;
import com.jaypal.authapp.token.exception.*;
import com.jaypal.authapp.user.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Slf4j
@Component
public class FailureReasonResolver {

    public AuthFailureReason resolve(Throwable ex) {
        Objects.requireNonNull(ex, "Exception cannot be null");

        Throwable root = unwrap(ex);

        // ---- AUTHENTICATION ----
        if (root instanceof BadCredentialsException ||
                root instanceof InvalidCredentialsException ||
                root instanceof UsernameNotFoundException) {
            return AuthFailureReason.INVALID_CREDENTIALS;
        }

        if (root instanceof DisabledException ||
                root instanceof UserAccountDisabledException) {
            return AuthFailureReason.ACCOUNT_DISABLED;
        }

        if (root instanceof LockedException) {
            return AuthFailureReason.ACCOUNT_LOCKED;
        }

        if (root instanceof CredentialsExpiredException) {
            return AuthFailureReason.TOKEN_EXPIRED;
        }

        // ---- TOKEN ----
        if (root instanceof RefreshTokenExpiredException ||
                root instanceof PasswordResetTokenExpiredException ||
                root instanceof VerificationTokenExpiredException) {
            return AuthFailureReason.TOKEN_EXPIRED;
        }

        if (root instanceof RefreshTokenRevokedException) {
            return AuthFailureReason.TOKEN_REVOKED;
        }

        if (root instanceof RefreshTokenNotFoundException ||
                root instanceof InvalidRefreshTokenException ||
                root instanceof PasswordResetTokenInvalidException ||
                root instanceof VerificationTokenInvalidException) {
            return AuthFailureReason.TOKEN_INVALID;
        }

        if (root instanceof MissingRefreshTokenException) {
            return AuthFailureReason.TOKEN_MISSING;
        }

        // ---- REGISTRATION / ACCOUNT ----
        if (root instanceof EmailAlreadyExistsException ||
                root instanceof DataIntegrityViolationException) {
            return AuthFailureReason.EMAIL_ALREADY_EXISTS;
        }

        if (root instanceof EmailAlreadyVerifiedException) {
            return AuthFailureReason.EMAIL_ALREADY_VERIFIED;
        }

        if (root instanceof EmailNotRegisteredException) {
            return AuthFailureReason.EMAIL_NOT_REGISTERED;
        }

        if (root instanceof PasswordPolicyViolationException) {
            return AuthFailureReason.PASSWORD_POLICY_VIOLATION;
        }

        // ---- AUTHORIZATION ----
        if (root instanceof AccessDeniedException) {
            return AuthFailureReason.ACCESS_DENIED;
        }

        // ---- VALIDATION ----
        if (root instanceof MethodArgumentNotValidException ||
                root instanceof IllegalArgumentException) {
            return AuthFailureReason.VALIDATION_FAILED;
        }

        // ---- NOT FOUND ----
        if (root instanceof ResourceNotFoundException ||
                root instanceof AuthenticatedUserMissingException) {
            return AuthFailureReason.USER_NOT_FOUND;
        }

        log.warn(
                "Unmapped exception type for audit: {} (original: {})",
                root.getClass().getName(),
                ex.getClass().getName()
        );

        return AuthFailureReason.SYSTEM_ERROR;
    }

    /**
     * Unwraps Spring Security and nested exceptions safely.
     */
    private Throwable unwrap(Throwable ex) {
        Set<Throwable> visited = new HashSet<>();
        Throwable current = ex;

        while (current != null &&
                current.getCause() != null &&
                !visited.contains(current)) {

            visited.add(current);

            // Spring Security wrapper
            if (current instanceof InternalAuthenticationServiceException) {
                current = current.getCause();
                continue;
            }

            current = current.getCause();
        }

        return current != null ? current : ex;
    }
}
