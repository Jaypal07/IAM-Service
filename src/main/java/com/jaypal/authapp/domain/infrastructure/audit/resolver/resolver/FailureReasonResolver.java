package com.jaypal.authapp.domain.infrastructure.audit.resolver.resolver;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.domain.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenReuseDetectedException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenRevokedException;
import com.jaypal.authapp.domain.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.domain.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.domain.infrastructure.oauth.handler.OAuthAuthenticationException;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RateLimitExceededException;
import com.jaypal.authapp.exception.auth.*;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
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

        /* ===================== AUTHENTICATION ===================== */

        if (root instanceof BadCredentialsException || root instanceof UsernameNotFoundException) {
            return AuthFailureReason.INVALID_CREDENTIALS;
        }

        if (root instanceof DisabledException) {
            return AuthFailureReason.ACCOUNT_DISABLED;
        }

        if (root instanceof LockedException) {
            return AuthFailureReason.ACCOUNT_LOCKED;
        }

        /* ===================== OAUTH ===================== */

        if (root instanceof OAuthAuthenticationException) {
            return AuthFailureReason.OAUTH_PROVIDER_ERROR;
        }

        /* ===================== TOKEN ===================== */

        if (root instanceof MissingRefreshTokenException) {
            return AuthFailureReason.TOKEN_MISSING;
        }

        if (root instanceof RefreshTokenExpiredException ||
                root instanceof VerificationTokenExpiredException) {
            return AuthFailureReason.TOKEN_EXPIRED;
        }

        if (root instanceof RefreshTokenRevokedException) {
            return AuthFailureReason.TOKEN_REVOKED;
        }

        if (root instanceof InvalidRefreshTokenException ||
                root instanceof VerificationTokenInvalidException) {
            return AuthFailureReason.TOKEN_INVALID;
        }

        if (root instanceof RefreshTokenReuseDetectedException) {
            return AuthFailureReason.TOKEN_REFRESH_REUSED;
        }

        /* ===================== PASSWORD ===================== */

        if (root instanceof PasswordPolicyViolationException) {
            return AuthFailureReason.PASSWORD_POLICY_VIOLATION;
        }

        if (root instanceof PasswordResetTokenInvalidException) {
            return AuthFailureReason.PASSWORD_RESET_TOKEN_INVALID;
        }

        if (root instanceof PasswordResetTokenExpiredException) {
            return AuthFailureReason.PASSWORD_RESET_TOKEN_EXPIRED;
        }

        if (root instanceof PasswordResetTokenUsedException) {
            return AuthFailureReason.PASSWORD_RESET_TOKEN_USED;
        }

        /* ===================== EMAIL / REGISTRATION ===================== */

        if (root instanceof EmailAlreadyExistsException) {
            return AuthFailureReason.EMAIL_ALREADY_EXISTS;
        }

        if (root instanceof EmailAlreadyVerifiedException) {
            return AuthFailureReason.EMAIL_ALREADY_VERIFIED;
        }

        if (root instanceof EmailNotRegisteredException) {
            return AuthFailureReason.EMAIL_NOT_REGISTERED;
        }

        /* ===================== AUTHORIZATION ===================== */

        if (root instanceof AccessDeniedException) {
            return AuthFailureReason.ACCESS_DENIED;
        }

        /* ===================== RATE LIMIT ===================== */

        if (root instanceof RateLimitExceededException) {
            return AuthFailureReason.RATE_LIMIT_EXCEEDED;
        }

        /* ===================== VALIDATION ===================== */

        if (root instanceof MethodArgumentNotValidException ||
                root instanceof ConstraintViolationException ||
                root instanceof IllegalArgumentException) {
            return AuthFailureReason.VALIDATION_FAILED;
        }
        if (root instanceof CredentialsExpiredException) {
            return AuthFailureReason.PASSWORD_POLICY_VIOLATION;
        }


        /* ===================== NOT FOUND ===================== */

        if (root instanceof ResourceNotFoundException ||
                root instanceof AuthenticatedUserMissingException) {
            return AuthFailureReason.ADMIN_TARGET_NOT_FOUND;
        }

        /* ===================== FALLBACK ===================== */

        log.warn(
                "Unmapped exception type for audit: {} (original: {})",
                root.getClass().getName(),
                ex.getClass().getName()
        );

        return AuthFailureReason.SYSTEM_ERROR;
    }

    /**
     * Unwraps nested and Spring Security exceptions safely.
     */
    private Throwable unwrap(Throwable ex) {
        Set<Throwable> visited = new HashSet<>();
        Throwable current = ex;

        while (current != null &&
                current.getCause() != null &&
                !visited.contains(current)) {

            visited.add(current);

            if (current instanceof InternalAuthenticationServiceException) {
                current = current.getCause();
                continue;
            }

            current = current.getCause();
        }

        return current != null ? current : ex;
    }
}
