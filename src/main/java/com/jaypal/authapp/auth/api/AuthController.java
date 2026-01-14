package com.jaypal.authapp.auth.api;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.auth.dto.*;
import com.jaypal.authapp.auth.application.AuthService;
import com.jaypal.authapp.auth.facade.WebAuthFacade;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.security.ratelimit.LoginRateLimiter;
import com.jaypal.authapp.user.dto.UserCreateRequest;
import com.jaypal.authapp.user.mapper.UserMapper;
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

    // ✅ ADDED: rate limiter (no other fields changed)
    private final LoginRateLimiter loginRateLimiter;

    @AuthAudit(
            event = AuthAuditEvent.REGISTER,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "request"
    )
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(
            @RequestBody @Valid UserCreateRequest request
    ) {
        authService.register(request);

        log.debug("Registration successful for email: {}", maskEmail(request.email()));

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(Map.of(
                        "message", "Registration successful. Please verify your email.",
                        "status", "success"
                ));
    }

    @AuthAudit(
            event = AuthAuditEvent.EMAIL_VERIFY,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "token"
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

        log.debug("Email verified successfully");

        return ResponseEntity.ok(Map.of(
                "message", "Email verified successfully.",
                "status", "success"
        ));
    }

    @AuthAudit(
            event = AuthAuditEvent.EMAIL_VERIFICATION_RESEND,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "request"
    )
    @PostMapping("/resend-verification")
    public ResponseEntity<Map<String, String>> resendVerification(
            @RequestBody @Valid ResendVerificationRequest request
    ) {
        authService.resendVerification(request.email());

        return ResponseEntity.ok(Map.of(
                "message", "If your email is registered and unverified, a new verification email has been sent.",
                "status", "success"
        ));
    }

    @AuthAudit(
            event = AuthAuditEvent.LOGIN,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "request"
    )
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody @Valid LoginRequest request,
            HttpServletRequest httpRequest,     // ✅ ADDED
            HttpServletResponse response
    ) {
        // ✅ ADDED: rate limit check
        String ip = httpRequest.getRemoteAddr();
        loginRateLimiter.checkRateLimit(request.email(), ip);

        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email().toLowerCase().trim(),
                        request.password()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        final AuthPrincipal principal = (AuthPrincipal) authentication.getPrincipal();
        final AuthLoginResult result = webAuthFacade.login(principal, response);

        // ✅ ADDED: reset counters on success
        loginRateLimiter.recordSuccess(request.email(), ip);

        log.info("User logged in successfully - ID: {}", principal.getUserId());

        return ResponseEntity.ok(
                TokenResponse.of(
                        result.accessToken(),
                        jwtService.getAccessTtlSeconds(),
                        UserMapper.toResponse(result.user())
                )
        );
    }

    @AuthAudit(
            event = AuthAuditEvent.TOKEN_REFRESHED,
            subject = AuditSubjectType.ANONYMOUS,
            subjectParam = "request"
    )
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        final AuthLoginResult result = webAuthFacade.refresh(request, response);

        log.debug("Token refreshed successfully - User ID: {}", result.user().getId());

        return ResponseEntity.ok(
                TokenResponse.of(
                        result.accessToken(),
                        jwtService.getAccessTtlSeconds(),
                        UserMapper.toResponse(result.user())
                )
        );
    }

    @AuthAudit(
            event = AuthAuditEvent.LOGOUT,
            subject = AuditSubjectType.USER_ID,
            subjectParam = "request"
    )
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        webAuthFacade.logout(request, response);

        log.debug("User logged out successfully");

        return ResponseEntity.ok(Map.of(
                "message", "Logged out successfully.",
                "status", "success"
        ));
    }

    @AuthAudit(
            event = AuthAuditEvent.PASSWORD_RESET_REQUEST,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "request"
    )
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @RequestBody @Valid ForgotPasswordRequest request
    ) {
        authService.initiatePasswordReset(request.email());

        return ResponseEntity.ok(Map.of(
                "message", "If your email is registered, a password reset link has been sent.",
                "status", "success"
        ));
    }

    @AuthAudit(
            event = AuthAuditEvent.PASSWORD_RESET_RESULT,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "request"
    )
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(
            @RequestBody @Valid ResetPasswordRequest request
    ) {
        authService.resetPassword(request.token(), request.newPassword());

        log.debug("Password reset successful");

        return ResponseEntity.ok(Map.of(
                "message", "Password reset successful.",
                "status", "success"
        ));
    }

    private String maskEmail(String email) {
        if (email == null || email.length() <= 3) {
            return "***";
        }

        final int atIndex = email.indexOf('@');
        if (atIndex <= 0) {
            return email.substring(0, 2) + "***";
        }

        return email.substring(0, Math.min(2, atIndex)) + "***" + email.substring(atIndex);
    }
}
