package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.DomainException;

public class EmailAlreadyVerifiedException extends DomainException implements IdempotentNoOpException {
    public EmailAlreadyVerifiedException(String message) {
        super(message);
    }
}
