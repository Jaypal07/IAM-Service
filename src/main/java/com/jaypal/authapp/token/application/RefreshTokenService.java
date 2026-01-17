package com.jaypal.authapp.token.application;

import com.jaypal.authapp.security.ratelimit.*;
import com.jaypal.authapp.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.token.exception.RefreshTokenRevokedException;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final int MAX_TOKENS_PER_USER = 10;
    private static final long CLEANUP_RETENTION_DAYS = 30L;
    private static final int MAX_TOKEN_LENGTH = 2048;
    private static final int MAX_ISSUE_ATTEMPTS = 3;

    private final RefreshTokenRepository repository;
    private final RefreshTokenHasher tokenHasher;

    private final RedisRateLimiter rateLimiter;
    private final RateLimitProperties rateLimitProperties;

    /* =========================
       ISSUE TOKEN
       ========================= */

    @Transactional
    public IssuedRefreshToken issue(UUID userId, long ttlSeconds) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID must not be null");
        }
        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("TTL must be positive");
        }

        for (int attempt = 1; attempt <= MAX_ISSUE_ATTEMPTS; attempt++) {
            try {
                return issueInternal(userId, ttlSeconds);
            } catch (DataIntegrityViolationException ex) {
                log.warn(
                        "Refresh token hash collision | attempt={} userId={}",
                        attempt,
                        userId
                );
            }
        }

        throw new IllegalStateException("Failed to issue refresh token after retries");
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    protected IssuedRefreshToken issueInternal(UUID userId, long ttlSeconds) {
        Instant now = Instant.now();

        String rawToken = RefreshTokenGenerator.generate();
        String tokenHash = tokenHasher.hash(rawToken);

        log.debug(
                "Issuing refresh token | userId={} ttlSeconds={}",
                userId,
                ttlSeconds
        );

        RefreshToken token = RefreshToken.issue(
                tokenHash,
                userId,
                now,
                now.plusSeconds(ttlSeconds)
        );

        repository.saveAndFlush(token);

        enforceTokenLimit(userId);

        log.debug(
                "Refresh token issued | userId={} expiresAt={}",
                userId,
                token.getExpiresAt()
        );

        return new IssuedRefreshToken(rawToken, token.getExpiresAt());
    }

    /* =========================
       VALIDATE TOKEN
       ========================= */

    @Transactional
    public RefreshToken validate(String rawToken) {
        String token = normalize(rawToken);
        String tokenHash = tokenHasher.hash(token);

        log.debug(
                "Validating refresh token | hashPrefix={}",
                tokenHash.substring(0, 8)
        );

        RefreshToken stored = repository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Refresh token not found");
                    return new RefreshTokenNotFoundException();
                });

        Instant now = Instant.now();

        if (stored.isExpired(now)) {
            log.warn(
                    "Refresh token expired | userId={} expiresAt={}",
                    stored.getUserId(),
                    stored.getExpiresAt()
            );
            throw new RefreshTokenExpiredException();
        }

        if (stored.isRevoked()) {
            log.error(
                    "Revoked refresh token used | userId={} rotated={}",
                    stored.getUserId(),
                    stored.wasRotated()
            );

            if (stored.wasRotated()) {
                log.error(
                        "Refresh token reuse detected | userId={}",
                        stored.getUserId()
                );
                revokeAllForUser(stored.getUserId());
            }

            throw new RefreshTokenRevokedException();
        }

        log.debug(
                "Refresh token valid | userId={}",
                stored.getUserId()
        );

        return stored;
    }

    /* =========================
       ROTATE TOKEN
       ========================= */

    @Transactional
    public IssuedRefreshToken rotate(UUID tokenId, long ttlSeconds) {
        if (tokenId == null) {
            throw new IllegalArgumentException("Token ID must not be null");
        }
        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("TTL must be positive");
        }

        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                return rotateInternal(tokenId, ttlSeconds);
            } catch (ObjectOptimisticLockingFailureException ex) {
                log.warn(
                        "Optimistic lock during refresh rotation | tokenId={} attempt={}",
                        tokenId,
                        attempt
                );
                if (attempt == 3) {
                    throw ex;
                }
            }
        }

        throw new IllegalStateException("Unreachable");
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    protected IssuedRefreshToken rotateInternal(UUID tokenId, long ttlSeconds) {
        Instant now = Instant.now();

        RefreshToken current = repository.findById(tokenId)
                .orElseThrow(RefreshTokenNotFoundException::new);

        RateLimitContext ctx = new RateLimitContext(
                "/api/v1/auth/refresh",
                "POST",
                "refresh-rotate-user"
        );

        String key = "rl:refresh:rotate:user:" + current.getUserId();

        log.debug(
                "Applying refresh rotation rate limit | userId={} key={}",
                current.getUserId(),
                key
        );

        boolean allowed = rateLimiter.allow(
                key,
                rateLimitProperties.getRefreshRotate().getCapacity(),
                rateLimitProperties.getRefreshRotate().getRefillPerSecond(),
                ctx
        );

        if (!allowed) {
            log.warn(
                    "Refresh rotation rate limit exceeded | userId={} capacity={} refillPerSecond={}",
                    current.getUserId(),
                    rateLimitProperties.getRefreshRotate().getCapacity(),
                    rateLimitProperties.getRefreshRotate().getRefillPerSecond()
            );
            throw new RateLimitExceededException("Too many refresh token attempts");
        }

        if (!current.isActive(now)) {
            log.warn(
                    "Inactive refresh token rotation attempt | userId={}",
                    current.getUserId()
            );
            throw new RefreshTokenRevokedException();
        }

        String nextRaw = RefreshTokenGenerator.generate();
        String nextHash = tokenHasher.hash(nextRaw);

        log.debug(
                "Rotating refresh token | userId={} oldHashPrefix={} newHashPrefix={}",
                current.getUserId(),
                current.getTokenHash().substring(0, 8),
                nextHash.substring(0, 8)
        );

        RefreshToken next = RefreshToken.issue(
                nextHash,
                current.getUserId(),
                now,
                now.plusSeconds(ttlSeconds)
        );

        current.rotate(nextHash, now);

        repository.save(next);
        repository.saveAndFlush(current);

        log.debug(
                "Refresh token rotated | userId={} newExpiresAt={}",
                current.getUserId(),
                next.getExpiresAt()
        );

        return new IssuedRefreshToken(nextRaw, next.getExpiresAt());
    }

    /* =========================
       REVOKE TOKEN
       ========================= */

    @Transactional
    public void revoke(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }

        String token = normalize(rawToken);
        String hash = tokenHasher.hash(token);

        repository.findByTokenHash(hash).ifPresent(tokenEntity -> {
            if (tokenEntity.isActive(Instant.now())) {
                log.debug(
                        "Revoking refresh token | userId={}",
                        tokenEntity.getUserId()
                );
                tokenEntity.revoke(Instant.now());
                repository.save(tokenEntity);
            }
        });
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeAllForUser(UUID userId) {
        if (userId == null) {
            return;
        }
        log.warn(
                "Revoking all refresh tokens | userId={}",
                userId
        );

        int revoked = repository.revokeAllActiveByUserId(userId);

        log.info(
                "All refresh tokens revoked after permission change | userId={} count={}",
                userId,
                revoked
        );
    }

    /* =========================
       CLEANUP
       ========================= */

    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        Instant cutoff = Instant.now().minusSeconds(CLEANUP_RETENTION_DAYS * 86400L);
        int deleted = repository.deleteByExpiresAtBefore(cutoff);

        if (deleted > 0) {
            log.info(
                    "Expired refresh tokens cleaned | count={}",
                    deleted
            );
        }
    }

    /* =========================
       HELPERS
       ========================= */

    private void enforceTokenLimit(UUID userId) {
        long active = repository.countByUserIdAndRevokedFalse(userId);

        if (active <= MAX_TOKENS_PER_USER) {
            return;
        }

        int revokeCount = (int) (active - MAX_TOKENS_PER_USER);

        log.warn(
                "Refresh token limit exceeded | userId={} active={} revokeCount={}",
                userId,
                active,
                revokeCount
        );

        repository.revokeOldestActiveTokens(userId, revokeCount);
    }

    private String normalize(String raw) {
        if (raw == null) {
            throw new RefreshTokenNotFoundException();
        }

        String token = raw.trim();
        if (token.startsWith("Bearer ")) {
            token = token.substring(7).trim();
        }

        if (token.isBlank()
                || token.length() > MAX_TOKEN_LENGTH
                || !token.matches("^[A-Za-z0-9._~-]+$")) {
            throw new RefreshTokenNotFoundException();
        }

        return token;
    }
}
