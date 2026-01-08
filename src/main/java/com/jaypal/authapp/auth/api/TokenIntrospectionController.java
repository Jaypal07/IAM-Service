package com.jaypal.authapp.auth.api;

import com.jaypal.authapp.auth.dto.TokenIntrospectionResponse;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class TokenIntrospectionController {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @PostMapping("/introspect")
    public TokenIntrospectionResponse introspect(
            @RequestHeader(name = "Authorization", required = false) String header
    ) {
        if (header == null || !header.startsWith("Bearer ")) {
            return TokenIntrospectionResponse.inactive();
        }

        Jws<Claims> parsed;
        try {
            parsed = jwtService.parse(header.substring(7).trim());
        } catch (JwtException ex) {
            return TokenIntrospectionResponse.inactive();
        }

        if (!jwtService.isAccessToken(parsed)) {
            return TokenIntrospectionResponse.inactive();
        }

        Claims claims = parsed.getBody();
        UUID userId = jwtService.extractUserId(claims);
        long tokenPv = jwtService.extractPermissionVersion(claims);

        User user = userRepository.findById(userId).orElse(null);
        if (user == null || user.getPermissionVersion() != tokenPv) {
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
    }
}
