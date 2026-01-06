package com.jaypal.authapp.common.exception.refresh;

import com.jaypal.authapp.common.exception.base.SecurityException;

public class InvalidRefreshTokenException extends SecurityException {
    public InvalidRefreshTokenException() {
        super("Invalid refresh token");
    }
}
