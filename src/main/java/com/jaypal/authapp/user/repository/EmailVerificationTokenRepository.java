package com.jaypal.authapp.user.repository;

import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface EmailVerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {

    Optional<VerificationToken> findByToken(String token);
    Optional<VerificationToken> findByUserId(UUID userId);
    void deleteByUser_Id(UUID userId);
}
