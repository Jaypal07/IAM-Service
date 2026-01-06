package com.jaypal.authapp.exception.email;

import com.jaypal.authapp.exception.base.DomainException;

public class EmailNotRegisteredException extends DomainException {
    public EmailNotRegisteredException() {
        super("Email not registered");
    }
}
