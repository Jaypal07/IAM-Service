package com.jaypal.authapp.exception.refresh;

import com.jaypal.authapp.exception.base.SecurityException;

public class MissingRefreshTokenException extends SecurityException {
    public MissingRefreshTokenException() {
        super("Refresh token missing");
    }
}
