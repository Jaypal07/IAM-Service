package com.jaypal.authapp.auth.controller;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.model.AuthAuditEvent;
import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.LoginRequest;
import com.jaypal.authapp.auth.dto.ResetPasswordRequest;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.auth.service.AuthService;
import com.jaypal.authapp.auth.service.EmailVerificationService;
import com.jaypal.authapp.dto.ForgotPasswordRequest;
import com.jaypal.authapp.dto.UserCreateRequest;
import com.jaypal.authapp.infrastructure.cookie.CookieService;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.service.RefreshTokenService;
import com.jaypal.authapp.user.mapper.UserMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AuthService authService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CookieService cookieService;
    private final EmailVerificationService emailVerificationService;

    // ---------------- REGISTER ----------------

    @AuthAudit(event = AuthAuditEvent.REGISTER)
    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestBody @Valid UserCreateRequest request
    ) {
        authService.register(request);
        return ResponseEntity
                .status(201)
                .body("Registration successful. Please verify your email.");
    }

    // ---------------- EMAIL VERIFY ----------------

    @GetMapping("/email-verify")
    public ResponseEntity<String> verifyEmail(
            @RequestParam String token
    ) {
        emailVerificationService.verifyEmail(token);
        return ResponseEntity.ok("Email verified successfully.");
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(
            @RequestParam String email
    ) {
        emailVerificationService.resendVerificationToken(email);
        return ResponseEntity.noContent().build();
    }

    // ---------------- LOGIN ----------------

    @AuthAudit(event = AuthAuditEvent.LOGIN_SUCCESS)
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response
    ) {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.email(),
                                request.password()
                        )
                );

        SecurityContextHolder
                .getContext()
                .setAuthentication(authentication);

        AuthPrincipal principal =
                (AuthPrincipal) authentication.getPrincipal();

        AuthLoginResult result =
                authService.login(principal);

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

    @AuthAudit(event = AuthAuditEvent.TOKEN_ROTATION)
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        String refreshJwt =
                readRefreshToken(request)
                        .orElseThrow(() ->
                                new BadCredentialsException(
                                        "Refresh token missing"
                                )
                        );

        Jws<Claims> parsed;
        try {
            parsed = jwtService.parse(refreshJwt);
        } catch (JwtException ex) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        if (!jwtService.isRefreshToken(parsed)) {
            throw new BadCredentialsException("Invalid token type");
        }

        Claims claims = parsed.getBody();
        UUID userId = UUID.fromString(claims.getSubject());
        String jti = claims.getId();

        RefreshToken current =
                refreshTokenService.validate(jti, userId);

        RefreshToken next =
                refreshTokenService.rotate(
                        current,
                        jwtService.getRefreshTtlSeconds()
                );

        String accessToken =
                jwtService.generateAccessToken(current.getUser());

        String newRefreshToken =
                jwtService.generateRefreshToken(
                        current.getUser(),
                        next.getJti()
                );

        cookieService.attachRefreshCookie(
                response,
                newRefreshToken,
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

    @AuthAudit(event = AuthAuditEvent.LOGOUT)
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        readRefreshToken(request).ifPresent(token -> {
            try {
                Jws<Claims> parsed = jwtService.parse(token);
                if (jwtService.isRefreshToken(parsed)) {
                    UUID userId =
                            UUID.fromString(
                                    parsed.getBody().getSubject()
                            );
                    refreshTokenService.revokeAllForUser(userId);
                }
            } catch (JwtException ignored) {
            }
        });

        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
        SecurityContextHolder.clearContext();

        return ResponseEntity.noContent().build();
    }

    // ---------------- FORGOT PASSWORD ----------------

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(
            @RequestBody ForgotPasswordRequest request
    ) {
        authService.initiatePasswordReset(request.email());
        return ResponseEntity.noContent().build();
    }

    // ---------------- RESET PASSWORD ----------------

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(
            @RequestBody ResetPasswordRequest request
    ) {
        authService.resetPassword(
                request.token(),
                request.newPassword()
        );
        return ResponseEntity.ok("Password reset successful.");
    }

    // ---------------- HELPERS ----------------

    private Optional<String> readRefreshToken(
            HttpServletRequest request
    ) {

        if (request.getCookies() != null) {
            Optional<String> cookieToken =
                    Arrays.stream(request.getCookies())
                            .filter(cookie ->
                                    cookieService
                                            .getRefreshTokenCookieName()
                                            .equals(cookie.getName())
                            )
                            .map(Cookie::getValue)
                            .filter(value -> !value.isBlank())
                            .findFirst();

            if (cookieToken.isPresent()) {
                return cookieToken;
            }
        }

        String headerToken =
                request.getHeader("X-Refresh-Token");
        if (headerToken != null && !headerToken.isBlank()) {
            return Optional.of(headerToken.trim());
        }

        String authHeader =
                request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null &&
                authHeader.toLowerCase().startsWith("bearer ")) {
            return Optional.of(authHeader.substring(7).trim());
        }

        return Optional.empty();
    }
}
