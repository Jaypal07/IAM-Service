package com.jaypal.authapp.common.exception.refresh;

import com.jaypal.authapp.common.exception.base.SecurityException;

public abstract class RefreshTokenException extends SecurityException {

    protected RefreshTokenException(String message) {
        super(message);
    }
}
