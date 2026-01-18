package com.jaypal.authapp.dto.user;

import jakarta.validation.constraints.*;

import java.util.Set;

public record AdminUserCreateRequest(

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Pattern(
                regexp = "^(?!.*\\$).*$",
                message = "Invalid email format"
        )
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
        String name,

        Set<@NotBlank String> roles
) {}
