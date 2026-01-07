package com.jaypal.authapp.user.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "roles")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(of = "type")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, unique = true, updatable = false)
    private RoleType type;

    @Column(nullable = false)
    private String description;

    @Column(nullable = false, updatable = false)
    private boolean immutable;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;
}

