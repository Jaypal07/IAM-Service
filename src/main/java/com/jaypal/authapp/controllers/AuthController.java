package com.jaypal.authapp.controllers;

import com.jaypal.authapp.dtos.LoginRequest;
import com.jaypal.authapp.dtos.RefreshTokenRequest;
import com.jaypal.authapp.dtos.TokenResponse;
import com.jaypal.authapp.dtos.UserDto;
import com.jaypal.authapp.entities.RefreshToken;
import com.jaypal.authapp.entities.User;
import com.jaypal.authapp.repositories.RefreshTokenRepository;
import com.jaypal.authapp.repositories.UserRepository;
import com.jaypal.authapp.security.CookieService;
import com.jaypal.authapp.security.JwtService;
import com.jaypal.authapp.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    // ---------------- REGISTER ----------------

    @PostMapping
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(authService.registerUser(userDto));
    }

    // ---------------- LOGIN ----------------

    @Transactional
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
    ) {
        Authentication authentication = authenticate(loginRequest);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();

        //revoke old refresh tokens (single-session behavior)
        refreshTokenRepository.revokeAllActiveByUserId(user.getId());

        String jti = UUID.randomUUID().toString();

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, jti);

        cookieService.attachRefreshCookie(
                response,
                refreshToken,
                (int) jwtService.getRefreshTtlSeconds()
        );
        cookieService.addNoStoreHeader(response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        accessToken,
                        jwtService.getAccessTtlSeconds(),
                        modelMapper.map(user, UserDto.class)
                )
        );
    }


    // ---------------- REFRESH ----------------

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String refreshToken = readRefreshToken(body, request)
                .orElseThrow(() -> new BadCredentialsException("Refresh token is missing"));

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);

        RefreshToken storedToken = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException("Refresh token not recognized"));

        if (storedToken.isRevoked()) {
            throw new BadCredentialsException("Refresh token revoked");
        }

        if (storedToken.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token expired");
        }

        if (!storedToken.getUser().getId().equals(userId)) {
            throw new BadCredentialsException("Token user mismatch");
        }

        // Rotate refresh token
        storedToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storedToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(storedToken);

        RefreshToken newTokenEntity = RefreshToken.builder()
                .jti(newJti)
                .user(storedToken.getUser())
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        refreshTokenRepository.save(newTokenEntity);

        String newAccessToken = jwtService.generateAccessToken(storedToken.getUser());
        String newRefreshToken = jwtService.generateRefreshToken(
                storedToken.getUser(),
                newJti
        );

        cookieService.attachRefreshCookie(
                response,
                newRefreshToken,
                (int) jwtService.getRefreshTtlSeconds()
        );
        cookieService.addNoStoreHeader(response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        newAccessToken,
                        jwtService.getAccessTtlSeconds(),
                        modelMapper.map(storedToken.getUser(), UserDto.class)
                )
        );
    }

    // ---------------- LOGOUT ----------------

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        readRefreshToken(null, request).ifPresent(token -> {
            try {
                if (jwtService.isRefreshToken(token)) {
                    refreshTokenRepository.findByJti(jwtService.getJti(token))
                            .ifPresent(rt -> {
                                rt.setRevoked(true);
                                refreshTokenRepository.save(rt);
                            });
                }
            } catch (Exception ignored) {
            }
        });

        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
        SecurityContextHolder.clearContext();

        return ResponseEntity.noContent().build();
    }

    // ---------------- HELPERS ----------------

    private Optional<String> readRefreshToken(
            RefreshTokenRequest body,
            HttpServletRequest request
    ) {
        // 1. Cookie (preferred)
        if (request.getCookies() != null) {
            Optional<String> cookieToken = Arrays.stream(request.getCookies())
                    .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                    .map(Cookie::getValue)
                    .filter(v -> !v.isBlank())
                    .findFirst();

            if (cookieToken.isPresent()) {
                return cookieToken;
            }
        }

        // 2. Body (optional)
        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }

        // 3. Header
        String headerToken = request.getHeader("X-Refresh-Token");
        if (headerToken != null && !headerToken.isBlank()) {
            return Optional.of(headerToken.trim());
        }

        // 4. Authorization Bearer
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            String candidate = authHeader.substring(7).trim();
            if (!candidate.isEmpty()) {
                return Optional.of(candidate);
            }
        }

        return Optional.empty();
    }

    private Authentication authenticate(LoginRequest request) {
        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.email(),
                            request.password()
                    )
            );
        } catch (Exception ex) {
            throw new BadCredentialsException("Invalid username or password");
        }
    }

}
