package com.jaypal.authapp.token.exception;

import com.jaypal.authapp.shared.exception.SecurityException;

public abstract class RefreshTokenException extends SecurityException {

    protected RefreshTokenException(String message) {
        super(message);
    }
}
