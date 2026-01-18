package com.jaypal.authapp.dto.user;

import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RoleDto {
    private UUID id;
    @Pattern(
            regexp = "^[a-zA-Z0-9 _.-]{2,50}$",
            message = "Name contains invalid characters"
    )
    private String name;
}
