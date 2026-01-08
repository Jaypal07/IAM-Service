package com.jaypal.authapp.user.exception;

import org.springframework.security.authentication.DisabledException;

public class UserAccountDisabledException extends DisabledException {
    public UserAccountDisabledException() {
        super("User account is disabled");
    }
}
