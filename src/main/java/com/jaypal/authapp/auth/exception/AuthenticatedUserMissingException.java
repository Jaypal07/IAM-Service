package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.SecurityException;

public class AuthenticatedUserMissingException extends SecurityException {
    public AuthenticatedUserMissingException() {
        super("Authenticated user not found");
    }
}
