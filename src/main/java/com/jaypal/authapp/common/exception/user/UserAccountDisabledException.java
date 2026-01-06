package com.jaypal.authapp.common.exception.user;

import org.springframework.security.authentication.DisabledException;

public class UserAccountDisabledException extends DisabledException {
    public UserAccountDisabledException() {
        super("User account is disabled");
    }
}
