package com.jaypal.authapp.token.application;

import com.jaypal.authapp.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.token.exception.RefreshTokenUserMismatchException;
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

    // ---------- ISSUE ----------

    @Transactional
    public RefreshToken issue(User user, long ttlSeconds) {

        RefreshToken token = RefreshToken.builder()
                .jti(UUID.randomUUID().toString())
                .user(user)
                .expiresAt(Instant.now().plusSeconds(ttlSeconds))
                .build();

        return repository.save(token);
    }

    // ---------- VALIDATE ----------

    @Transactional
    public RefreshToken validate(String jti, UUID userId) {

        RefreshToken token = repository.findForRefresh(jti)
                .orElseThrow(() -> {
                    log.error(
                            "REFRESH INVALID: token not found. jti={}, userId={}",
                            jti, userId
                    );
                    return new RefreshTokenNotFoundException();
                });

        if (!token.getUser().getId().equals(userId)) {
            log.error(
                    "REFRESH INVALID: user mismatch. jti={}, tokenUser={}, requestUser={}",
                    jti, token.getUser().getId(), userId
            );
            throw new RefreshTokenUserMismatchException();
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            log.warn(
                    "REFRESH EXPIRED. jti={}, exp={}",
                    jti, token.getExpiresAt()
            );
            throw new RefreshTokenExpiredException();
        }

        if (token.isRevoked()) {

            if (token.getReplacedByToken() != null) {
                log.warn(
                        "REFRESH REUSE BLOCKED. oldJti={}, replacedBy={}",
                        jti, token.getReplacedByToken()
                );
            } else {
                log.warn(
                        "REFRESH REVOKED (logout/admin). jti={}",
                        jti
                );
            }

            throw new RefreshTokenExpiredException();
        }

        log.info(
                "REFRESH VALIDATED. jti={}, userId={}",
                jti, userId
        );

        return token;
    }

    // ---------- ROTATE ----------

    @Transactional
    public RefreshToken rotate(RefreshToken current, long ttlSeconds) {

        try {
            String nextJti = UUID.randomUUID().toString();

            current.revoke(nextJti);
            repository.save(current);

            RefreshToken next = RefreshToken.builder()
                    .jti(nextJti)
                    .user(current.getUser())
                    .expiresAt(Instant.now().plusSeconds(ttlSeconds))
                    .build();

            log.info(
                    "ROTATING refresh token. oldJti={}, newJti={}, userId={}",
                    current.getJti(),
                    nextJti,
                    current.getUser().getId()
            );

            return repository.save(next);

        } catch (OptimisticLockException ex) {

            log.warn(
                    "REFRESH RACE LOST. jti={}, userId={}",
                    current.getJti(),
                    current.getUser().getId()
            );

            current.revoke();
            repository.save(current);

            throw new RefreshTokenExpiredException();
        }
    }

    // ---------- LOGOUT (SINGLE SESSION) ----------

    @Transactional
    public void revoke(String jti, UUID userId) {

        repository.findByJtiAndUserId(jti, userId)
                .ifPresent(token -> {
                    if (!token.isRevoked()) {
                        token.revoke();
                        repository.save(token);
                    }
                });
    }

    // ---------- ADMIN / SECURITY ----------

    @Transactional
    public void revokeAllForUser(UUID userId) {
        repository.revokeAllActiveByUserId(userId);
    }
}
