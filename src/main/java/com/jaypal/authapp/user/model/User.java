package com.jaypal.authapp.user.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Entity
@Table(
        name = "users",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "jk_users_provider_provider_id",
                        columnNames = {"provider", "provider_id"}
                ),
                @UniqueConstraint(
                        name = "users_email",
                        columnNames = {"email"}
                )
        }
)
@Getter
@Setter(AccessLevel.PRIVATE)
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID id;

    @Column(nullable = false)
    private String email;

    private String password;

    @Column(nullable = false)
    private String name;

    private String image;

    @Column(nullable = false)
    private boolean enabled;

    @Column(nullable = false)
    private long permissionVersion;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Provider provider;

    @Column(name = "provider_id", nullable = false)
    private String providerId;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    @OneToMany(
            mappedBy = "user",
            fetch = FetchType.LAZY,
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @Builder.Default
    private Set<UserRole> userRoles = new HashSet<>();

    // ---------- FACTORIES ----------

    public static User createLocal(String email, String password, String name) {
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();

        return User.builder()
                .id(id)
                .email(email)
                .password(password)
                .permissionVersion(0L)
                .name(name)
                .enabled(false)
                .provider(Provider.LOCAL)
                .providerId(id.toString())
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    public static User createOAuth(
            Provider provider,
            String providerId,
            String email,
            String name,
            String image
    ) {
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();

        return User.builder()
                .id(id)
                .email(email)
                .name(name)
                .image(image)
                .enabled(true)
                .permissionVersion(0L)
                .provider(provider)
                .providerId(providerId)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    // ---------- DOMAIN ----------

    /**
     * JWT SAFE.
     * Returns role names exactly as before.
     */
    public Set<String> getRoles() {
        return userRoles.stream()
                .map(ur -> ur.getRole().getType().name())
                .collect(Collectors.toUnmodifiableSet());
    }

    public Set<Role> getRoleEntities() {
        return userRoles.stream()
                .map(UserRole::getRole)
                .collect(Collectors.toUnmodifiableSet());
    }

    public void enable() {
        this.enabled = true;
        this.updatedAt = Instant.now();
    }

    public void disable() {
        this.enabled = false;
        this.updatedAt = Instant.now();
    }

    public void changePassword(String encodedPassword) {
        this.password = encodedPassword;
        this.updatedAt = Instant.now();
    }

    public void updateProfile(String name, String image) {
        if (name != null) this.name = name;
        if (image != null) this.image = image;
        this.updatedAt = Instant.now();
    }

    public void bumpPermissionVersion() {
        this.permissionVersion++;
        this.updatedAt = Instant.now();
    }

}
