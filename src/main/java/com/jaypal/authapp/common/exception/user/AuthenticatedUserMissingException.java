package com.jaypal.authapp.common.exception.user;

import com.jaypal.authapp.common.exception.base.SecurityException;

public class AuthenticatedUserMissingException extends SecurityException {
    public AuthenticatedUserMissingException() {
        super("Authenticated user not found");
    }
}
