package com.jaypal.authapp.common.exception.refresh;

import com.jaypal.authapp.common.exception.base.SecurityException;

public class MissingRefreshTokenException extends SecurityException {
    public MissingRefreshTokenException() {
        super("Refresh token missing");
    }
}
