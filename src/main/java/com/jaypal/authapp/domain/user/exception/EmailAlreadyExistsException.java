package com.jaypal.authapp.domain.user.exception;

import com.jaypal.authapp.exception.DomainException;

public class EmailAlreadyExistsException extends DomainException {
    public EmailAlreadyExistsException() {
        super("Email already exists");
    }
}
