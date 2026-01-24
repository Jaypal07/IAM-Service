package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.DomainException;

public class EmailNotRegisteredException extends DomainException implements IdempotentNoOpException {
    public EmailNotRegisteredException() {
        super("Email not registered");
    }
}
