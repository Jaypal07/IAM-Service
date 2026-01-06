package com.jaypal.authapp.exception.user;

import com.jaypal.authapp.exception.base.SecurityException;

public class PasswordResetTokenExpiredException extends SecurityException {
    public PasswordResetTokenExpiredException() {
        super("Password reset token expired or used");
    }
}
