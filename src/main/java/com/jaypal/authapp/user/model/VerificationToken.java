package com.jaypal.authapp.user.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Entity
@Table(
        name = "verification_token",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "verification_token_user_id_key",
                        columnNames = {"user_id"}
                ),
                @UniqueConstraint(
                        name = "verification_token_token_key",
                        columnNames = {"token"}
                )
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class VerificationToken {

    private static final long EXPIRY_MINUTES = 15;

    @Id
    @GeneratedValue()
    @UuidGenerator(style = UuidGenerator.Style.TIME)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private Instant expiryDate;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    public VerificationToken(User user) {
        this.user = user;
        regenerate();
    }

    public void regenerate() {
        this.token = UUID.randomUUID().toString();
        this.expiryDate = Instant.now().plus(EXPIRY_MINUTES, ChronoUnit.MINUTES);
    }

    public boolean isExpired() {
        return expiryDate.isBefore(Instant.now());
    }
}
