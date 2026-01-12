package com.jaypal.authapp.token.repository;

import com.jaypal.authapp.token.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    Optional<RefreshToken> findByTokenHashAndUserId(String tokenHash, UUID userId);

    List<RefreshToken> findAllByUserIdAndRevokedFalse(UUID userId);

    long countByUserIdAndRevokedFalse(UUID userId);

    @Query("""
            SELECT rt FROM RefreshToken rt
            WHERE rt.userId = :userId 
            AND rt.revoked = false
            AND rt.expiresAt > CURRENT_TIMESTAMP
            ORDER BY rt.issuedAt ASC
            LIMIT :limit
            """)
    List<RefreshToken> findOldestActiveTokensByUserId(
            @Param("userId") UUID userId,
            @Param("limit") int limit
    );

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :cutoff")
    int deleteByExpiresAtBefore(@Param("cutoff") Instant cutoff);

    @Modifying
    @Query("""
        update RefreshToken t
        set t.revoked = true
        where t.userId = :userId
          and t.revoked = false
    """)
    int revokeAllActiveByUserId(@Param("userId") UUID userId);

    @Modifying
    @Query(value = """
        update refresh_tokens
        set revoked = true
        where id in (
            select id from refresh_tokens
            where user_id = :userId
              and revoked = false
            order by issued_at asc
            limit :limit
        )
    """, nativeQuery = true)
    int revokeOldestActiveTokens(
            @Param("userId") UUID userId,
            @Param("limit") int limit
    );

}

/*
CHANGELOG:
1. Added countByUserIdAndRevokedFalse for token limit enforcement
2. Added findOldestActiveTokensByUserId for LRU-style token eviction
3. Added deleteByExpiresAtBefore with @Modifying for bulk cleanup
4. Used @Query with JPQL for better performance on complex queries
5. Added @Param annotations for clarity
6. Used LIMIT in JPQL for oldest tokens query
7. Made deleteByExpiresAtBefore return int for deleted count
*/