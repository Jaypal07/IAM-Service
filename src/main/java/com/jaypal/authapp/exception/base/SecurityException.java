package com.jaypal.authapp.exception.base;

public abstract class SecurityException extends RuntimeException {

    protected SecurityException(String message) {
        super(message);
    }
}
