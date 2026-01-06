package com.jaypal.authapp.common.exception.user;

import com.jaypal.authapp.common.exception.base.SecurityException;

public class PasswordResetTokenExpiredException extends SecurityException {
    public PasswordResetTokenExpiredException() {
        super("Password reset token expired or used");
    }
}
