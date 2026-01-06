package com.jaypal.authapp.exception.refresh;

import com.jaypal.authapp.exception.base.SecurityException;

public abstract class RefreshTokenException extends SecurityException {

    protected RefreshTokenException(String message) {
        super(message);
    }
}
