package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.DomainException;

public class EmailAlreadyVerifiedException extends DomainException {
    public EmailAlreadyVerifiedException(String message) {
        super(message);
    }
}
