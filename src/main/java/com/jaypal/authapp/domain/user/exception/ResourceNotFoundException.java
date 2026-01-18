package com.jaypal.authapp.domain.user.exception;

import com.jaypal.authapp.exception.DomainException;

public class ResourceNotFoundException extends DomainException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException() {
        super("Resource Not Found!!");
    }
}
