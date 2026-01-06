package com.jaypal.authapp.common.exception.email;

import com.jaypal.authapp.common.exception.base.DomainException;

public class EmailAlreadyExistsException extends DomainException {
    public EmailAlreadyExistsException() {
        super("Email already exists");
    }
}
