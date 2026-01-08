package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.SecurityException;

public class PasswordResetTokenInvalidException extends SecurityException {
    public PasswordResetTokenInvalidException() {
        super("Password reset token invalid");
    }
}
