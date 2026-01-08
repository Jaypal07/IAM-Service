package com.jaypal.authapp.auth.dto;

import com.jaypal.authapp.audit.domain.HasEmail;

public record ResendVerificationRequest(String email)
        implements HasEmail {

    @Override
    public String getEmail() {
        return email;
    }
}
