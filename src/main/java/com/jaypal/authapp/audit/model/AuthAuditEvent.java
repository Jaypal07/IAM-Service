package com.jaypal.authapp.audit.model;

public enum AuthAuditEvent {

    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    REGISTER_AND_LOGIN,

    OAUTH_LOGIN_SUCCESS,
    OAUTH_LOGIN_FAILURE,

    TOKEN_REFRESH,
    TOKEN_ROTATION,
    TOKEN_REVOKED,

    LOGOUT,
    ACCOUNT_DISABLED
}
