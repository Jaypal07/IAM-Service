package com.jaypal.authapp.exception.email;

import com.jaypal.authapp.exception.base.DomainException;

public class EmailAlreadyExistsException extends DomainException {
    public EmailAlreadyExistsException() {
        super("Email already exists");
    }
}
