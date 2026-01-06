package com.jaypal.authapp.common.exception.user;

import com.jaypal.authapp.common.exception.base.DomainException;

public class PasswordPolicyViolationException extends DomainException {
    public PasswordPolicyViolationException() {
        super("Password too short");
    }
}
