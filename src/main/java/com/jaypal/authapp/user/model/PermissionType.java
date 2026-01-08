package com.jaypal.authapp.user.model;

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

    // SECURITY
    TOKEN_REVOKE,
    SESSION_TERMINATE,

    // AUDIT
    AUDIT_READ;
}
