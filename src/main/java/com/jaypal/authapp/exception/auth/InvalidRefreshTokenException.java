package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.SecurityException;

public class InvalidRefreshTokenException extends SecurityException {
    public InvalidRefreshTokenException(String refreshTokenTooLong) {
        super(refreshTokenTooLong);
    }
}
