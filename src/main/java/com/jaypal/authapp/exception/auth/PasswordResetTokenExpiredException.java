package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.SecurityException;

public class PasswordResetTokenExpiredException extends SecurityException {
    public PasswordResetTokenExpiredException() {
        super("Password reset token expired or used");
    }
}
