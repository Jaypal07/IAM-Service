package com.jaypal.authapp.auth.exception;

import org.springframework.security.core.AuthenticationException;

public class EmailNotVerifiedException extends AuthenticationException {
    public EmailNotVerifiedException() {
        super("Email not verified");
    }
}