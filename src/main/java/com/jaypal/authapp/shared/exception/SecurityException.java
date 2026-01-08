package com.jaypal.authapp.shared.exception;

public abstract class SecurityException extends RuntimeException {

    protected SecurityException(String message) {
        super(message);
    }
}
