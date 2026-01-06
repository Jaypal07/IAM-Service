package com.jaypal.authapp.exception.user;

import com.jaypal.authapp.exception.base.DomainException;

public class PasswordPolicyViolationException extends DomainException {
    public PasswordPolicyViolationException() {
        super("Password too short");
    }
}
