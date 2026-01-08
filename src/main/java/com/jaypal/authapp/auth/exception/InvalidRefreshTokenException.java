package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.SecurityException;

public class InvalidRefreshTokenException extends SecurityException {
    public InvalidRefreshTokenException() {
        super("Invalid refresh token");
    }
}
