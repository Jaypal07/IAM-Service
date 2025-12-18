package com.jaypal.authapp.auth.controller;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.LoginRequest;
import com.jaypal.authapp.auth.dto.RefreshTokenRequest;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.auth.service.AuthService;
import com.jaypal.authapp.dto.ForgotPasswordRequest;
import com.jaypal.authapp.dto.UserCreateRequest;
import com.jaypal.authapp.security.cookie.CookieService;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.service.RefreshTokenService;
import com.jaypal.authapp.user.mapper.UserMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AuthService authApplicationService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CookieService cookieService;

    // ---------------- Register ----------------

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(
            @RequestBody @Valid UserCreateRequest request,
            HttpServletResponse response
    ) {

        // Create user
        var user = authApplicationService.register(request);

        // Auto-login after register (optional but common)
        var result = authApplicationService.issueTokens(user);

        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                (int) result.refreshTtlSeconds()
        );
        cookieService.addNoStoreHeader(response);

        return ResponseEntity.status(201).body(
                TokenResponse.of(
                        result.accessToken(),
                        jwtService.getAccessTtlSeconds(),
                        UserMapper.toResponse(user)
                )
        );
    }


    // ---------------- LOGIN ----------------

    @Transactional
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response
    ) {

        Authentication authentication = authenticate(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthPrincipal principal =
                (AuthPrincipal) authentication.getPrincipal();

        AuthLoginResult result =
                authApplicationService.login(principal);

        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                (int) result.refreshTtlSeconds()
        );
        cookieService.addNoStoreHeader(response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        result.accessToken(),
                        jwtService.getAccessTtlSeconds(),
                        UserMapper.toResponse(result.user())
                )
        );
    }

    // ---------------- REFRESH ----------------

    @Transactional
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        String refreshJwt = readRefreshToken(body, request)
                .orElseThrow(() ->
                        new BadCredentialsException("Refresh token is missing"));

        if (!jwtService.isRefreshToken(refreshJwt)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        String jti = jwtService.getJti(refreshJwt);
        UUID userId = jwtService.getUserId(refreshJwt);

        RefreshToken current =
                refreshTokenService.validate(jti, userId);

        RefreshToken next =
                refreshTokenService.rotate(
                        current,
                        jwtService.getRefreshTtlSeconds()
                );

        String accessToken =
                jwtService.generateAccessToken(current.getUser());

        String newRefreshJwt =
                jwtService.generateRefreshToken(
                        current.getUser(),
                        next.getJti()
                );

        cookieService.attachRefreshCookie(
                response,
                newRefreshJwt,
                (int) jwtService.getRefreshTtlSeconds()
        );
        cookieService.addNoStoreHeader(response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        accessToken,
                        jwtService.getAccessTtlSeconds(),
                        UserMapper.toResponse(current.getUser())
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
                    refreshTokenService
                            .revokeIfExists(jwtService.getJti(token));
                }
            } catch (Exception ignored) {}
        });

        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
        SecurityContextHolder.clearContext();

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(
            @RequestBody ForgotPasswordRequest request
    ) {

        authApplicationService.initiatePasswordReset(request.email());

        // Always return 204 to prevent email enumeration
        return ResponseEntity.noContent().build();
    }


    // ---------------- HELPERS ----------------

    private Optional<String> readRefreshToken(
            RefreshTokenRequest body,
            HttpServletRequest request
    ) {

        if (request.getCookies() != null) {
            Optional<String> cookieToken = Arrays.stream(request.getCookies())
                    .filter(c ->
                            cookieService.getRefreshTokenCookieName()
                                    .equals(c.getName()))
                    .map(Cookie::getValue)
                    .filter(v -> !v.isBlank())
                    .findFirst();

            if (cookieToken.isPresent()) return cookieToken;
        }

        if (body != null && body.refreshToken() != null
                && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }

        String headerToken = request.getHeader("X-Refresh-Token");
        if (headerToken != null && !headerToken.isBlank()) {
            return Optional.of(headerToken.trim());
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            return Optional.of(authHeader.substring(7).trim());
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
