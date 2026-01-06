package com.jaypal.authapp.audit.validation;

import com.jaypal.authapp.audit.model.AuthAuditEvent;
import com.jaypal.authapp.audit.model.AuthFailureReason;

import java.util.*;

public final class AuthAuditMatrix {

    private static final Map<AuthAuditEvent, Set<AuthFailureReason>> MATRIX =
            new EnumMap<>(AuthAuditEvent.class);

    static {

        MATRIX.put(
                AuthAuditEvent.LOGIN_FAILURE,
                EnumSet.of(
                        AuthFailureReason.INVALID_CREDENTIALS,
                        AuthFailureReason.USER_NOT_FOUND,
                        AuthFailureReason.ACCOUNT_DISABLED,
                        AuthFailureReason.ACCOUNT_LOCKED
                )
        );

        MATRIX.put(
                AuthAuditEvent.OAUTH_LOGIN_FAILURE,
                EnumSet.of(
                        AuthFailureReason.INVALID_CREDENTIALS,
                        AuthFailureReason.ACCOUNT_DISABLED
                )
        );

        MATRIX.put(
                AuthAuditEvent.TOKEN_REFRESH,
                EnumSet.of(
                        AuthFailureReason.TOKEN_INVALID,
                        AuthFailureReason.TOKEN_EXPIRED,
                        AuthFailureReason.TOKEN_REVOKED
                )
        );

        MATRIX.put(
                AuthAuditEvent.TOKEN_ROTATION,
                EnumSet.of(
                        AuthFailureReason.TOKEN_INVALID,
                        AuthFailureReason.TOKEN_EXPIRED,
                        AuthFailureReason.TOKEN_REVOKED
                )
        );

        MATRIX.put(
                AuthAuditEvent.REGISTER,
                EnumSet.of(
                        AuthFailureReason.EMAIL_ALREADY_EXISTS,
                        AuthFailureReason.VALIDATION_FAILED
                )
        );

        MATRIX.put(
                AuthAuditEvent.EMAIL_VERIFY,
                EnumSet.of(
                        AuthFailureReason.TOKEN_INVALID,
                        AuthFailureReason.TOKEN_EXPIRED,
                        AuthFailureReason.EMAIL_ALREADY_VERIFIED
                )
        );

        MATRIX.put(
                AuthAuditEvent.EMAIL_VERIFICATION_RESEND,
                EnumSet.of(
                        AuthFailureReason.EMAIL_NOT_REGISTERED,
                        AuthFailureReason.EMAIL_ALREADY_VERIFIED,
                        AuthFailureReason.VALIDATION_FAILED
                )
        );

        MATRIX.put(
                AuthAuditEvent.PASSWORD_RESET_FAILURE,
                EnumSet.of(
                        AuthFailureReason.RESET_TOKEN_INVALID,
                        AuthFailureReason.RESET_TOKEN_EXPIRED,
                        AuthFailureReason.PASSWORD_POLICY_VIOLATION
                )
        );

        MATRIX.put(
                AuthAuditEvent.PASSWORD_CHANGE,
                EnumSet.of(
                        AuthFailureReason.INVALID_CREDENTIALS,
                        AuthFailureReason.PASSWORD_POLICY_VIOLATION
                )
        );

        MATRIX.put(
                AuthAuditEvent.ACCOUNT_DISABLED,
                EnumSet.of(AuthFailureReason.ACCOUNT_DISABLED)
        );
    }

    private AuthAuditMatrix() {}

    public static boolean isAllowed(
            AuthAuditEvent event,
            AuthFailureReason reason
    ) {
        if (reason == null || reason == AuthFailureReason.SYSTEM_ERROR) {
            return true;
        }

        Set<AuthFailureReason> allowed = MATRIX.get(event);

        if (allowed == null) {
            throw new IllegalStateException(
                    "AuthAuditMatrix missing configuration for event: " + event
            );
        }

        return allowed.contains(reason);
    }
}
