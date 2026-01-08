package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.DomainException;

public class EmailNotRegisteredException extends DomainException {
    public EmailNotRegisteredException() {
        super("Email not registered");
    }
}
