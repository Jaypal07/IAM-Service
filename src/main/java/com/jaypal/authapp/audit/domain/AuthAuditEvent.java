package com.jaypal.authapp.audit.domain;

public enum AuthAuditEvent {

    // ---------- AUTHENTICATION ----------
    LOGIN,
    LOGOUT,
    REGISTER,
    EMAIL_VERIFY,
    EMAIL_VERIFICATION_RESEND,
    OAUTH_LOGIN,

    // ---------- TOKEN ----------
    TOKEN_ISSUED,
    TOKEN_REFRESHED,
    TOKEN_REVOKED,

    // ---------- PASSWORD ----------
    PASSWORD_CHANGE,
    PASSWORD_RESET_REQUEST,
    PASSWORD_RESET_RESULT,

    // ---------- ACCOUNT ----------
    ACCOUNT_UPDATED,
    ACCOUNT_DISABLED,

    // ---------- AUTHORIZATION ----------
    ROLE_ASSIGNED,
    ROLE_REMOVED,
    PERMISSION_GRANTED,
    PERMISSION_REVOKED,

    // ---------- ADMIN ----------
    ADMIN_USER_CREATED,
    ADMIN_USER_UPDATED,
    TOKEN_INTROSPECTED,
    ADMIN_USER_DELETED,
    ADMIN_ACTION
}
