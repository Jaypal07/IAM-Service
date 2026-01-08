package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.SecurityException;

public class PasswordResetTokenExpiredException extends SecurityException {
    public PasswordResetTokenExpiredException() {
        super("Password reset token expired or used");
    }
}
