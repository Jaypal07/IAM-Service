package com.jaypal.authapp.user.model;

public enum RoleType {

    ROLE_USER,
    ROLE_ADMIN,
    ROLE_OWNER;

    public boolean isAdmin() {
        return this == ROLE_ADMIN || this == ROLE_OWNER;
    }

    public boolean isOwner() {
        return this == ROLE_OWNER;
    }
}
