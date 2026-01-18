package com.jaypal.authapp.domain.dto.user;

import com.jaypal.authapp.domain.audit.entity.HasEmail;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UserCreateRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Pattern(
                regexp = "^(?!.*\\$).*$",
                message = "Invalid email format"
        )
        @Size(max = 255, message = "Email must not exceed 255 characters")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        String password,

        @NotBlank(message = "Name is required")
        @Size(min = 1, max = 255, message = "Name must be between 1 and 255 characters")
        @Pattern(
                regexp = "^[a-zA-Z0-9 _.-]{2,50}$",
                message = "Name contains invalid characters"
        )
        String name
) implements HasEmail {
    @Override
    public String getEmail() {
        return email;
    }
}