package com.jaypal.authapp.dtos;

import com.jaypal.authapp.entities.Provider;
import com.jaypal.authapp.entities.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {
    private UUID id;
    private String email;
    private String password;
    private String name;
    private String image;
    private boolean enabled=true;
    private Instant createdAt =  Instant.now();
    private Instant updatedAt =  Instant.now();
    private Provider provider = Provider.LOCAL;

    private Set<RoleDto> roles = new HashSet<>();
}
