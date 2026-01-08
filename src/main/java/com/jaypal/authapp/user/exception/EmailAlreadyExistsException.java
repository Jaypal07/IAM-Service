package com.jaypal.authapp.user.exception;

import com.jaypal.authapp.shared.exception.DomainException;

public class EmailAlreadyExistsException extends DomainException {
    public EmailAlreadyExistsException() {
        super("Email already exists");
    }
}
