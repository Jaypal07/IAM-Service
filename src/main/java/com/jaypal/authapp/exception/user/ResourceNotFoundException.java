package com.jaypal.authapp.exception.user;

import com.jaypal.authapp.exception.base.DomainException;

public class ResourceNotFoundException extends DomainException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException() {
        super("Resource Not Found!!");
    }
}
