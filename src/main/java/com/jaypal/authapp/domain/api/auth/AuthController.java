package com.jaypal.authapp.domain.api.auth;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.config.properties.RateLimitProperties;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.domain.dto.auth.AuthLoginResult;
import com.jaypal.authapp.domain.dto.auth.LoginRequest;
import com.jaypal.authapp.domain.dto.auth.RefreshTokenRequest;
import com.jaypal.authapp.domain.dto.auth.TokenResponse;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RateLimitContext;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RateLimitExceededException;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RedisRateLimiter;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RequestIpResolver;
import com.jaypal.authapp.domain.service.auth.AuthService;
import com.jaypal.authapp.domain.service.auth.WebAuthFacade;
import com.jaypal.authapp.domain.infrastructure.security.jwt.JwtService;
import com.jaypal.authapp.domain.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.domain.dto.user.UserCreateRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final WebAuthFacade webAuthFacade;
    private final AuthService authService;
    private final JwtService jwtService;
    private final RedisRateLimiter rateLimiter;
    private final RateLimitProperties rateLimitProperties;

    @AuthAudit(
            event = AuthAuditEvent.LOGIN_SUCCESS,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "request"
    )
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody @Valid LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        final String email = request.email().toLowerCase().trim();
        final String ip = RequestIpResolver.resolve(httpRequest);

        final String emailKey = "rl:login:email:" + email;
        final String ipKey = "rl:login:ip:" + ip;

        RateLimitContext emailCtx = new RateLimitContext(
                "/api/v1/auth/login",
                "POST",
                "email"
        );

        if (!rateLimiter.allow(
                emailKey,
                rateLimitProperties.getLoginEmail().getCapacity(),
                rateLimitProperties.getLoginEmail().getRefillPerSecond(),
                emailCtx
        )) {
            log.warn("Login blocked by email rate limit. emailHash={}", email.hashCode());
            throw new RateLimitExceededException("Too many login attempts");
        }

        RateLimitContext ipCtx = new RateLimitContext(
                "/api/v1/auth/login",
                "POST",
                "ip"
        );

        if (!rateLimiter.allow(
                ipKey,
                rateLimitProperties.getLoginIp().getCapacity(),
                rateLimitProperties.getLoginIp().getRefillPerSecond(),
                ipCtx
        )) {
            log.warn("Login blocked by IP rate limit. ip={}", ip);
            throw new RateLimitExceededException("Too many login attempts");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.password())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthPrincipal principal = (AuthPrincipal) authentication.getPrincipal();
        AuthLoginResult result = webAuthFacade.login(principal, response);

        log.info("Login successful. userId={} ip={}", principal.getUserId(), ip);

        return ResponseEntity.ok(
                TokenResponse.of(
                        result.accessToken(),
                        jwtService.getAccessTtlSeconds(),
                        result.user()
                )
        );
    }

    @AuthAudit(
            event = AuthAuditEvent.REGISTER_SUCCESS,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "request"
    )
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(
            @RequestBody @Valid UserCreateRequest request
    ) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "message", "Registration successful. Please verify your email.",
                "status", "success"
        ));
    }

    /* ===================== EMAIL VERIFICATION ===================== */

    @AuthAudit(
            event = AuthAuditEvent.EMAIL_VERIFICATION_SUCCESS,
            subject = AuditSubjectType.SYSTEM
    )
    @GetMapping("/email-verify")
    public ResponseEntity<Map<String, String>> verifyEmail(
            @RequestParam
            @NotBlank
            @Pattern(
                    regexp = "^[0-9a-fA-F\\-]{36}$",
                    message = "Invalid verification token format"
            )
            String token
    ) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(Map.of(
                "message", "Email verified successfully.",
                "status", "success"
        ));
    }

    @AuthAudit(
            event = AuthAuditEvent.EMAIL_VERIFICATION_RESEND,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "email"
    )
    @PostMapping("/email-verify/resend")
    public ResponseEntity<Map<String, String>> resendVerification(
            @RequestParam @NotBlank String email
    ) {
        log.debug("Resend verification requested");
        authService.resendVerification(email);

        // Always return success to avoid user enumeration
        return ResponseEntity.ok(Map.of(
                "message", "If the email exists, a verification link has been sent.",
                "status", "success"
        ));
    }

    /* ===================== PASSWORD RESET ===================== */

    @AuthAudit(
            event = AuthAuditEvent.PASSWORD_RESET_REQUESTED,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "email"
    )
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> initiatePasswordReset(
            @RequestParam @NotBlank String email
    ) {
        log.debug("Password reset initiation requested");
        authService.initiatePasswordReset(email);

        // Always succeed to prevent user enumeration
        return ResponseEntity.ok(Map.of(
                "message", "If the email exists, a password reset link has been sent.",
                "status", "success"
        ));
    }

    @AuthAudit(
            event = AuthAuditEvent.PASSWORD_RESET_SUCCESS,
            subject = AuditSubjectType.SYSTEM
    )
    @PostMapping("/password-reset/confirm")
    public ResponseEntity<Map<String, String>> resetPassword(
            @RequestParam
            @NotBlank
            @Pattern(
                    regexp = "^[0-9a-fA-F\\-]{36}$",
                    message = "Invalid reset token format"
            )
            String token,
            @RequestParam @NotBlank String password
    ) {
        authService.resetPassword(token, password);

        return ResponseEntity.ok(Map.of(
                "message", "Password reset successful.",
                "status", "success"
        ));
    }

    @AuthAudit(
            event = AuthAuditEvent.TOKEN_REFRESH_SUCCESS,
            subject = AuditSubjectType.USER_ID
    )
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @RequestBody(required = false) RefreshTokenRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        final String ip = RequestIpResolver.resolve(httpRequest);

        log.debug("Refresh endpoint called | ip={}", ip);

        AuthLoginResult result = webAuthFacade.refresh(
                httpRequest,
                response,
                request
        );

        log.info(
                "Token refresh successful | userId={} ip={}",
                result.user().id(),
                ip
        );

        return ResponseEntity.ok(
                TokenResponse.of(
                        result.accessToken(),
                        jwtService.getAccessTtlSeconds(),
                        result.user()
                )
        );
    }


    @AuthAudit(
            event = AuthAuditEvent.LOGOUT_SINGLE_SESSION,
            subject = AuditSubjectType.USER_ID,
            subjectParam = "principal"
    )
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @AuthenticationPrincipal AuthPrincipal principal,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        webAuthFacade.logout(principal, request, response);
        SecurityContextHolder.clearContext();

        log.info(
                "Logout successful. userId={} ip={}",
                principal != null ? principal.getUserId() : "anonymous",
                RequestIpResolver.resolve(request)
        );

        return ResponseEntity.ok(Map.of(
                "message", "Logout successful.",
                "status", "success"
        ));
    }

}
