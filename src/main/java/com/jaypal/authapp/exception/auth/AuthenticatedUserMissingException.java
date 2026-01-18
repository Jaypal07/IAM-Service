package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.SecurityException;

public class AuthenticatedUserMissingException extends SecurityException {
    public AuthenticatedUserMissingException() {
        super("Authenticated user not found");
    }
}
