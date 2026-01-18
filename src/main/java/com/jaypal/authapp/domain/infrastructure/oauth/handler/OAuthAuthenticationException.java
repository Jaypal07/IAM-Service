package com.jaypal.authapp.domain.infrastructure.oauth.handler;

public class OAuthAuthenticationException extends RuntimeException {
    public OAuthAuthenticationException(String message) {
        super(message);
    }
}
