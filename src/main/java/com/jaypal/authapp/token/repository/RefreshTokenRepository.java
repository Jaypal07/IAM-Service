package com.jaypal.authapp.token.repository;

import com.jaypal.authapp.token.model.RefreshToken;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByJti(String jti);

    @Query("""
        select rt
        from RefreshToken rt
        join fetch rt.user u
        join fetch u.roles
        where rt.jti = :jti
    """)
    Optional<RefreshToken> findByJtiWithUser(@Param("jti") String jti);

    @Modifying
    @Query("""
        update RefreshToken rt
        set rt.revoked = true,
            rt.revokedAt = CURRENT_TIMESTAMP
        where rt.user.id = :userId
          and rt.revoked = false
    """)
    int revokeAllActiveByUserId(@Param("userId") UUID userId);
}
