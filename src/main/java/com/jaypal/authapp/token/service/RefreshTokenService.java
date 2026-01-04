package com.jaypal.authapp.token.service;

import com.jaypal.authapp.exception.refresh.*;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.repository.RefreshTokenRepository;
import com.jaypal.authapp.user.model.User;
import jakarta.persistence.OptimisticLockException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository repository;

    @Transactional
    public RefreshToken issue(User user, long ttlSeconds) {
        log.info("Issuing refresh token. userId={}", user.getId());

        repository.revokeAllActiveByUserId(user.getId());

        RefreshToken token = RefreshToken.builder()
                .jti(UUID.randomUUID().toString())
                .user(user)
                .expiresAt(Instant.now().plusSeconds(ttlSeconds))
                .build();

        return repository.save(token);
    }

    @Transactional
    public RefreshToken validate(String jti, UUID userId) {
        log.debug("Validating refresh token. userId={}", userId);

        RefreshToken token = repository.findByJtiWithUser(jti)
                .orElseThrow(() -> {
                    log.warn("Refresh token not found. userId={}", userId);
                    return new RefreshTokenNotFoundException();
                });

        if (!token.getUser().getId().equals(userId)) {
            log.warn("Refresh token user mismatch. userId={}", userId);
            throw new RefreshTokenUserMismatchException();
        }

        if (token.isRevoked()) {
            log.warn("Revoked refresh token used. userId={}", userId);
            repository.revokeAllActiveByUserId(userId);
            throw new RefreshTokenReuseDetectedException();
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            log.info("Expired refresh token. userId={}", userId);
            throw new RefreshTokenExpiredException();
        }

        return token;
    }

    @Transactional
    public RefreshToken rotate(RefreshToken current, long ttlSeconds) {
        log.info("Rotating refresh token. userId={}", current.getUser().getId());

        try {
            String newJti = UUID.randomUUID().toString();
            current.revoke(newJti);
            repository.save(current);

            RefreshToken next = RefreshToken.builder()
                    .jti(newJti)
                    .user(current.getUser())
                    .expiresAt(Instant.now().plusSeconds(ttlSeconds))
                    .build();

            return repository.save(next);

        } catch (OptimisticLockException ex) {
            log.error("Optimistic lock failed. Refresh token reuse suspected. userId={}",
                    current.getUser().getId());
            repository.revokeAllActiveByUserId(current.getUser().getId());
            throw new RefreshTokenReuseDetectedException();
        }
    }

    @Transactional
    public void revokeAllForUser(UUID userId) {
        log.info("Revoking all refresh tokens. userId={}", userId);
        repository.revokeAllActiveByUserId(userId);
    }
}
