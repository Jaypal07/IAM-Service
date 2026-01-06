package com.jaypal.authapp.exception.user;

import com.jaypal.authapp.exception.base.SecurityException;

public class AuthenticatedUserMissingException extends SecurityException {
    public AuthenticatedUserMissingException() {
        super("Authenticated user not found");
    }
}
