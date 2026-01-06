package com.jaypal.authapp.common.exception.base;

public abstract class SecurityException extends RuntimeException {

    protected SecurityException(String message) {
        super(message);
    }
}
