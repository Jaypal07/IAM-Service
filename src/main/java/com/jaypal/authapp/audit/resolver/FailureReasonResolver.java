package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuthFailureReason;
import com.jaypal.authapp.auth.exception.*;
import com.jaypal.authapp.auth.exception.InvalidRefreshTokenException;
import com.jaypal.authapp.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.token.exception.RefreshTokenUserMismatchException;
import com.jaypal.authapp.auth.exception.PasswordPolicyViolationException;
import com.jaypal.authapp.auth.exception.PasswordResetTokenExpiredException;
import com.jaypal.authapp.auth.exception.PasswordResetTokenInvalidException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.*;
import org.springframework.stereotype.Component;

@Component
public class FailureReasonResolver {

    public AuthFailureReason resolve(AuthAuditEvent event, Throwable ex) {

        // ---------- LOGIN / OAUTH ----------

        if (event == AuthAuditEvent.LOGIN_FAILURE
                || event == AuthAuditEvent.OAUTH_LOGIN_FAILURE) {

            if (ex instanceof BadCredentialsException)
                return AuthFailureReason.INVALID_CREDENTIALS;

            if (ex instanceof DisabledException)
                return AuthFailureReason.ACCOUNT_DISABLED;

            if (ex instanceof LockedException)
                return AuthFailureReason.ACCOUNT_LOCKED;

            return AuthFailureReason.SYSTEM_ERROR;
        }

        // ---------- REGISTER ----------

        if (event == AuthAuditEvent.REGISTER) {

            if (ex instanceof EmailAlreadyExistsException
                    || ex instanceof DataIntegrityViolationException)
                return AuthFailureReason.EMAIL_ALREADY_EXISTS;

            if (ex instanceof PasswordPolicyViolationException)
                return AuthFailureReason.VALIDATION_FAILED;

            return AuthFailureReason.SYSTEM_ERROR;
        }

        // ---------- EMAIL VERIFY ----------

        if (event == AuthAuditEvent.EMAIL_VERIFY) {

            if (ex instanceof VerificationTokenExpiredException)
                return AuthFailureReason.TOKEN_EXPIRED;

            if (ex instanceof VerificationTokenInvalidException)
                return AuthFailureReason.TOKEN_INVALID;

            if (ex instanceof EmailAlreadyVerifiedException)
                return AuthFailureReason.EMAIL_ALREADY_VERIFIED;

            return AuthFailureReason.SYSTEM_ERROR;
        }

        // ---------- EMAIL VERIFICATION RESEND ----------

        if (event == AuthAuditEvent.EMAIL_VERIFICATION_RESEND) {

            if (ex instanceof EmailNotRegisteredException)
                return AuthFailureReason.EMAIL_NOT_REGISTERED;

            if (ex instanceof EmailAlreadyVerifiedException)
                return AuthFailureReason.EMAIL_ALREADY_VERIFIED;

            return AuthFailureReason.SYSTEM_ERROR;
        }

        // ---------- TOKEN ----------

        if (event == AuthAuditEvent.TOKEN_REFRESH
                || event == AuthAuditEvent.TOKEN_ROTATION) {

            if (ex instanceof RefreshTokenExpiredException)
                return AuthFailureReason.TOKEN_EXPIRED;

            if (ex instanceof RefreshTokenNotFoundException
                    || ex instanceof RefreshTokenUserMismatchException
                    || ex instanceof InvalidRefreshTokenException)
                return AuthFailureReason.TOKEN_INVALID;

            return AuthFailureReason.SYSTEM_ERROR;
        }

        // ---------- PASSWORD RESET ----------

        if (event == AuthAuditEvent.PASSWORD_RESET_FAILURE) {

            if (ex instanceof PasswordResetTokenExpiredException)
                return AuthFailureReason.RESET_TOKEN_EXPIRED;

            if (ex instanceof PasswordResetTokenInvalidException)
                return AuthFailureReason.RESET_TOKEN_INVALID;

            if (ex instanceof PasswordPolicyViolationException)
                return AuthFailureReason.PASSWORD_POLICY_VIOLATION;

            return AuthFailureReason.SYSTEM_ERROR;
        }

        // ---------- PASSWORD CHANGE ----------

        if (event == AuthAuditEvent.PASSWORD_CHANGE) {

            if (ex instanceof BadCredentialsException)
                return AuthFailureReason.INVALID_CREDENTIALS;

            if (ex instanceof PasswordPolicyViolationException)
                return AuthFailureReason.PASSWORD_POLICY_VIOLATION;

            return AuthFailureReason.SYSTEM_ERROR;
        }

        // ---------- FALLBACK ----------

        return AuthFailureReason.SYSTEM_ERROR;
    }
}
