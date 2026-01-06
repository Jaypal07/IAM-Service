package com.jaypal.authapp.exception.refresh;

import com.jaypal.authapp.exception.base.SecurityException;

public class InvalidRefreshTokenException extends SecurityException {
    public InvalidRefreshTokenException() {
        super("Invalid refresh token");
    }
}
