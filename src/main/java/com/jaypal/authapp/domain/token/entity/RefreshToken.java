package com.jaypal.authapp.domain.token.entity;

import com.jaypal.authapp.domain.token.exception.RefreshTokenStateException;
import jakarta.persistence.*;
import lombok.Getter;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Getter
@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_refresh_token_hash", columnList = "token_hash", unique = true),
                @Index(name = "idx_refresh_tokens_user_revoked", columnList = "user_id, revoked"),
                @Index(name = "idx_refresh_tokens_user_issued", columnList = "user_id, revoked, issued_at"),
                @Index(name = "idx_refresh_tokens_expires_at", columnList = "expires_at")
        }
)
public class RefreshToken {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Version
    private Long version;

    @Column(name = "token_hash", nullable = false, updatable = false, length = 64)
    private String tokenHash;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "issued_at", nullable = false, updatable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "replaced_by_token_hash", length = 64)
    private String replacedByTokenHash;

    protected RefreshToken() {
    }

    private RefreshToken(
            UUID id,
            String tokenHash,
            UUID userId,
            Instant issuedAt,
            Instant expiresAt
    ) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.tokenHash = requireNonBlank(tokenHash, "tokenHash");
        this.userId = Objects.requireNonNull(userId, "userId must not be null");
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        this.revoked = false;
    }

    public static RefreshToken issue(
            String tokenHash,
            UUID userId,
            Instant issuedAt,
            Instant expiresAt
    ) {
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
        }

        return new RefreshToken(
                UUID.randomUUID(),
                tokenHash,
                userId,
                issuedAt,
                expiresAt
        );
    }

    public void revoke(Instant now) {
        requireActive(now);
        this.revoked = true;
        this.revokedAt = now;
    }

    public void rotate(String newTokenHash, Instant now) {
        requireActive(now);
        this.revoked = true;
        this.revokedAt = now;
        this.replacedByTokenHash = requireNonBlank(newTokenHash, "newTokenHash");
    }

    public boolean isExpired(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        return !now.isBefore(expiresAt);
    }

    public boolean isActive(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        return !revoked && !isExpired(now);
    }

    public boolean wasRotated() {
        return replacedByTokenHash != null && !replacedByTokenHash.isBlank();
    }

    private void requireActive(Instant now) {
        if (revoked) {
            throw new RefreshTokenStateException("Token already revoked");
        }
        if (isExpired(now)) {
            throw new RefreshTokenStateException("Token expired");
        }
    }

    private static String requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be null or blank");
        }
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken other)) return false;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return 31;
    }
}
