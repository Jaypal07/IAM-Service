package com.jaypal.authapp.exception.auth;

import org.springframework.security.core.AuthenticationException;

public class AuthenticatedUserMissingException extends AuthenticationException {
    public AuthenticatedUserMissingException() {
        super("Authenticated user not found");
    }
}
