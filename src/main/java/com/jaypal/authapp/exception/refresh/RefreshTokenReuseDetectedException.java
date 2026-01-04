package com.jaypal.authapp.exception.refresh;

import org.springframework.security.authentication.CredentialsExpiredException;

public class RefreshTokenReuseDetectedException
        extends CredentialsExpiredException {

    public RefreshTokenReuseDetectedException() {
        super("Refresh token reuse detected. Session terminated.");
    }
}
