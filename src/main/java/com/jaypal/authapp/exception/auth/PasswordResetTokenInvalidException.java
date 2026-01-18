package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.SecurityException;

public class PasswordResetTokenInvalidException extends SecurityException {
    public PasswordResetTokenInvalidException() {
        super("Password reset token invalid");
    }
}
