package com.jaypal.authapp.domain.user.exception;

import com.jaypal.authapp.exception.DomainException;
import com.jaypal.authapp.exception.auth.BusinessRejectionException;

public class EmailAlreadyExistsException extends DomainException implements BusinessRejectionException {
    public EmailAlreadyExistsException() {
        super("Email already exists");
    }
}
