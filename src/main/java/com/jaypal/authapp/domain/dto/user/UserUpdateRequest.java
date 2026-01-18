package com.jaypal.authapp.domain.dto.user;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UserUpdateRequest(
        @Size(min = 1, max = 255, message = "Name must be between 1 and 255 characters")
        @Pattern(
                regexp = "^[a-zA-Z0-9 _.-]{2,50}$",
                message = "Name contains invalid characters"
        )
        String name,

        @Size(max = 512, message = "Image URL must not exceed 512 characters")
        String image,

        @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        String password
) {}