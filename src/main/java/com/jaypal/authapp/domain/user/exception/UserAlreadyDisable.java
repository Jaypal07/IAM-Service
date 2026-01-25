package com.jaypal.authapp.domain.user.exception;

import com.jaypal.authapp.exception.DomainException;

public class UserAlreadyDisable extends DomainException {
    public UserAlreadyDisable() {
        super("User is already disable");
    }
}
