package com.jaypal.authapp.user.dto;

import com.jaypal.authapp.audit.domain.HasEmail;

public record UserCreateRequest(String email, String password, String name)
        implements HasEmail {

        @Override
        public String getEmail() {
                return email;
        }
}
