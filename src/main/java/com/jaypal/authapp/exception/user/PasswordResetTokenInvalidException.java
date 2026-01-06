package com.jaypal.authapp.exception.user;

import com.jaypal.authapp.exception.base.SecurityException;

public class PasswordResetTokenInvalidException extends SecurityException {
    public PasswordResetTokenInvalidException() {
        super("Password reset token invalid");
    }
}
