package com.jaypal.authapp.domain.service.auth;

import com.jaypal.authapp.domain.dto.auth.TokenIntrospectionResponse;
import com.jaypal.authapp.domain.infrastructure.security.jwt.JwtService;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenIntrospectionService {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public TokenIntrospectionResponse introspect(String rawToken) {
        try {
            Jws<Claims> parsed = jwtService.parseAccessToken(rawToken);
            Claims claims = parsed.getBody();

            UUID userId = jwtService.extractUserId(claims);
            long tokenPv = jwtService.extractPermissionVersion(claims);

            User user = userRepository.findById(userId).orElse(null);
            if (user == null) {
                log.debug("Token introspection failed. User not found: {}", userId);
                return TokenIntrospectionResponse.inactive();
            }

            if (user.getPermissionVersion() != tokenPv) {
                log.debug("Token introspection failed. Permission version mismatch for user {}", userId);
                return TokenIntrospectionResponse.inactive();
            }

            return new TokenIntrospectionResponse(
                    true,
                    userId,
                    jwtService.extractEmail(claims),
                    jwtService.extractRoles(claims),
                    jwtService.extractPermissions(claims),
                    claims.getExpiration().toInstant().getEpochSecond()
            );

        } catch (JwtException ex) {
            log.debug("Token introspection failed. Invalid JWT: {}", ex.getMessage());
            return TokenIntrospectionResponse.inactive();
        }
    }
}
