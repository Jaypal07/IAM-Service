package com.jaypal.authapp.auth.dto;

import com.jaypal.authapp.audit.domain.HasEmail;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record ForgotPasswordRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Pattern(
                regexp = "^(?!.*\\$).*$",
                message = "Invalid email format"
        )
        String email
) implements HasEmail {
    @Override
    public String getEmail() {
        return email;
    }
}