package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.SecurityException;

public class MissingRefreshTokenException extends SecurityException {
    public MissingRefreshTokenException() {
        super("Refresh token missing");
    }
}
