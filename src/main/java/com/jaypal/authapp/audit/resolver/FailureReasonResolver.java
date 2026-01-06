package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.model.*;
import com.jaypal.authapp.exception.email.*;
import io.jsonwebtoken.*;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.*;
import org.springframework.stereotype.Component;

@Component
public class FailureReasonResolver {

    public AuthFailureReason resolve(AuthAuditEvent event, Throwable ex) {

        if (event == AuthAuditEvent.LOGIN_FAILURE
                || event == AuthAuditEvent.OAUTH_LOGIN_FAILURE) {

            if (ex instanceof BadCredentialsException) return AuthFailureReason.INVALID_CREDENTIALS;
            if (ex instanceof DisabledException) return AuthFailureReason.ACCOUNT_DISABLED;
            if (ex instanceof LockedException) return AuthFailureReason.ACCOUNT_LOCKED;
        }

        if (event == AuthAuditEvent.REGISTER) {
            if (ex instanceof DataIntegrityViolationException)
                return AuthFailureReason.EMAIL_ALREADY_EXISTS;
            if (ex instanceof IllegalArgumentException)
                return AuthFailureReason.VALIDATION_FAILED;
        }

        if (event == AuthAuditEvent.EMAIL_VERIFY) {
            if (ex instanceof ExpiredJwtException || ex instanceof VerificationException)
                return AuthFailureReason.TOKEN_EXPIRED;
            if (ex instanceof JwtException || ex instanceof IllegalArgumentException)
                return AuthFailureReason.TOKEN_INVALID;
            if (ex instanceof EmailAlreadyVerifiedException)
                return AuthFailureReason.EMAIL_ALREADY_VERIFIED;
        }

        if (event == AuthAuditEvent.TOKEN_REFRESH
                || event == AuthAuditEvent.TOKEN_ROTATION) {

            if (ex instanceof ExpiredJwtException)
                return AuthFailureReason.TOKEN_EXPIRED;
            if (ex instanceof JwtException || ex instanceof IllegalArgumentException)
                return AuthFailureReason.TOKEN_INVALID;
        }

        if (event == AuthAuditEvent.PASSWORD_RESET_FAILURE) {
            if (ex instanceof ExpiredJwtException)
                return AuthFailureReason.RESET_TOKEN_EXPIRED;
            if (ex instanceof JwtException || ex instanceof IllegalArgumentException)
                return AuthFailureReason.RESET_TOKEN_INVALID;
        }

        if (event == AuthAuditEvent.PASSWORD_CHANGE) {
            if (ex instanceof BadCredentialsException)
                return AuthFailureReason.INVALID_CREDENTIALS;
            if (ex instanceof IllegalArgumentException)
                return AuthFailureReason.PASSWORD_POLICY_VIOLATION;
        }

        if (event == AuthAuditEvent.EMAIL_VERIFICATION_RESEND) {
            if (ex instanceof EmailNotRegisteredException)
                return AuthFailureReason.EMAIL_NOT_REGISTERED;
            if (ex instanceof EmailAlreadyVerifiedException)
                return AuthFailureReason.EMAIL_ALREADY_VERIFIED;
        }

        return AuthFailureReason.SYSTEM_ERROR;
    }
}
