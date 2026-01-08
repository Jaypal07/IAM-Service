package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.SecurityException;

public class MissingRefreshTokenException extends SecurityException {
    public MissingRefreshTokenException() {
        super("Refresh token missing");
    }
}
