package com.jaypal.authapp.domain.user.entity;

public enum PermissionType {

    // USER MANAGEMENT
    USER_READ,
    USER_UPDATE,
    USER_DISABLE,
    USER_ROLE_ASSIGN,

    // ROLE & PERMISSION ADMIN
    ROLE_READ,
    ROLE_MANAGE,
    PERMISSION_READ,
    PERMISSION_MANAGE,
    RATE_LIMIT_RESET,

    // SECURITY
    TOKEN_REVOKE,
    SESSION_TERMINATE,

    // AUDIT
    AUDIT_READ,
    USER_CREATE;
}
