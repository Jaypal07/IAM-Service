package com.jaypal.authapp.token.application;

import com.jaypal.authapp.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.token.exception.RefreshTokenRevokedException;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
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
                log.warn("Refresh token collision, retry {}", attempt);
            }
        }

        throw new IllegalStateException("Failed to issue refresh token after retries");
    }

    private IssuedRefreshToken issueInternal(UUID userId, long ttlSeconds) {
        Instant now = Instant.now();

        String rawToken = RefreshTokenGenerator.generate();
        String tokenHash = tokenHasher.hash(rawToken);

        RefreshToken token = RefreshToken.issue(
                tokenHash,
                userId,
                now,
                now.plusSeconds(ttlSeconds)
        );

        repository.save(token);
        enforceTokenLimit(userId);

        return new IssuedRefreshToken(rawToken, token.getExpiresAt());
    }

    @Transactional(readOnly = true)
    public RefreshToken validate(String rawToken) {
        String token = normalize(rawToken);
        String tokenHash = tokenHasher.hash(token);

        RefreshToken stored = repository.findByTokenHash(tokenHash)
                .orElseThrow(RefreshTokenNotFoundException::new);

        Instant now = Instant.now();

        if (stored.isRevoked()) {
            if (stored.wasRotated()) {
                log.error("Refresh token reuse detected. userId={}", stored.getUserId());
                revokeAllForUser(stored.getUserId());
            }
            throw new RefreshTokenRevokedException();
        }

        if (stored.isExpired(now)) {
            throw new RefreshTokenExpiredException();
        }

        return stored;
    }

    @Retryable(
            retryFor = ObjectOptimisticLockingFailureException.class,
            maxAttempts = 3,
            backoff = @Backoff(delay = 100, multiplier = 2)
    )
    @Transactional
    public IssuedRefreshToken rotate(RefreshToken current, long ttlSeconds) {
        if (current == null) {
            throw new IllegalArgumentException("Current token must not be null");
        }
        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("TTL must be positive");
        }

        Instant now = Instant.now();

        String nextRaw = RefreshTokenGenerator.generate();
        String nextHash = tokenHasher.hash(nextRaw);

        current.rotate(nextHash, now);

        RefreshToken next = RefreshToken.issue(
                nextHash,
                current.getUserId(),
                now,
                now.plusSeconds(ttlSeconds)
        );

        repository.save(current);
        repository.save(next);

        return new IssuedRefreshToken(nextRaw, next.getExpiresAt());
    }

    @Transactional
    public void revoke(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }

        String token = normalize(rawToken);
        String tokenHash = tokenHasher.hash(token);

        repository.findByTokenHash(tokenHash).ifPresent(t -> {
            if (t.isActive(Instant.now())) {
                t.revoke(Instant.now());
                repository.save(t);
            }
        });
    }

    @Transactional
    public void revokeAllForUser(UUID userId) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID must not be null");
        }
        repository.revokeAllActiveByUserId(userId);
    }

    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        Instant cutoff = Instant.now().minusSeconds(CLEANUP_RETENTION_DAYS * 86400L);
        repository.deleteByExpiresAtBefore(cutoff);
    }

    private void enforceTokenLimit(UUID userId) {
        long active = repository.countByUserIdAndRevokedFalse(userId);
        if (active > MAX_TOKENS_PER_USER) {
            repository.revokeOldestActiveTokens(
                    userId,
                    (int) (active - MAX_TOKENS_PER_USER)
            );
        }
    }

    private String normalize(String raw) {
        if (raw == null) {
            throw new RefreshTokenNotFoundException();
        }

        String token = raw.trim();
        if (token.startsWith("Bearer ")) {
            token = token.substring(7).trim();
        }

        if (token.isBlank() || token.length() > MAX_TOKEN_LENGTH) {
            throw new RefreshTokenNotFoundException();
        }

        return token;
    }
}
