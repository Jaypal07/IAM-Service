package com.jaypal.authapp.common.exception.email;

import com.jaypal.authapp.common.exception.base.DomainException;

public class EmailNotRegisteredException extends DomainException {
    public EmailNotRegisteredException() {
        super("Email not registered");
    }
}
