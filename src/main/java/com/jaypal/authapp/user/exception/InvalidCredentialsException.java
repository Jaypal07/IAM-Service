package com.jaypal.authapp.user.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class InvalidCredentialsException extends BadCredentialsException {
    public InvalidCredentialsException() {
        super("Invalid credentials");
    }
}
