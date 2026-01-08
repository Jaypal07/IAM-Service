package com.jaypal.authapp.user.exception;

import com.jaypal.authapp.shared.exception.DomainException;

public class ResourceNotFoundException extends DomainException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException() {
        super("Resource Not Found!!");
    }
}
