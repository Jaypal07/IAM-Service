package com.jaypal.authapp.domain.token.exception;

import com.jaypal.authapp.exception.SecurityException;

public abstract class RefreshTokenException extends SecurityException {

    protected RefreshTokenException(String message) {
        super(message);
    }
}
