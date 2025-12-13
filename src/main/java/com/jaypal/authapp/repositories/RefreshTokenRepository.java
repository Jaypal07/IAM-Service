package com.jaypal.authapp.repositories;

import com.jaypal.authapp.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByJti(String refreshToken);
    @Modifying
    @Query("""
        update RefreshToken rt
        set rt.revoked = true
        where rt.user.id = :userId
          and rt.revoked = false
    """)
    void revokeAllActiveByUserId(@Param("userId") UUID userId);
}
