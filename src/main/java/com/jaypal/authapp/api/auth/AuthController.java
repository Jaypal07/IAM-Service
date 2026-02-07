package com.jaypal.authapp.api.auth;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.config.properties.RateLimitProperties;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.dto.auth.*;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitContext;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitExceededException;
import com.jaypal.authapp.infrastructure.ratelimit.RedisRateLimiter;
import com.jaypal.authapp.infrastructure.ratelimit.RequestIpResolver;
import com.jaypal.authapp.service.auth.AuthService;
import com.jaypal.authapp.service.auth.WebAuthFacade;
import com.jaypal.authapp.infrastructure.security.jwt.JwtService;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.dto.user.UserCreateRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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

@Tag(name = "Authentication", description = "Authentication and authorization endpoints for user login, registration, email verification, and password management")
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

        @Operation(summary = "User login", description = "Authenticate user with email and password. Returns JWT access token and sets HTTP-only refresh token cookie. Rate limited by both email and IP address.")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Login successful", content = @Content(schema = @Schema(implementation = TokenResponse.class))),
                        @ApiResponse(responseCode = "401", description = "Invalid credentials"),
                        @ApiResponse(responseCode = "403", description = "Account disabled or email not verified"),
                        @ApiResponse(responseCode = "429", description = "Too many login attempts")
        })
        @AuthAudit(event = AuthAuditEvent.LOGIN, subject = AuditSubjectType.EMAIL, subjectParam = "request")
        @PostMapping("/login")
        public ResponseEntity<TokenResponse> login(
                        @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Login credentials", required = true) @RequestBody @Valid LoginRequest request,
                        HttpServletRequest httpRequest,
                        HttpServletResponse response) {
                final String email = request.email().toLowerCase().trim();
                final String ip = RequestIpResolver.resolve(httpRequest);

                final String emailKey = "rl:login:email:" + email;
                final String ipKey = "rl:login:ip:" + ip;

                RateLimitContext emailCtx = new RateLimitContext(
                                "/api/v1/auth/login",
                                "POST",
                                "email");

                if (!rateLimiter.allow(
                                emailKey,
                                rateLimitProperties.getLoginEmail().getCapacity(),
                                rateLimitProperties.getLoginEmail().getRefillPerSecond(),
                                emailCtx)) {
                        log.warn("Login blocked by email rate limit. emailHash={}", email.hashCode());
                        throw new RateLimitExceededException("Too many login attempts");
                }

                RateLimitContext ipCtx = new RateLimitContext(
                                "/api/v1/auth/login",
                                "POST",
                                "ip");

                if (!rateLimiter.allow(
                                ipKey,
                                rateLimitProperties.getLoginIp().getCapacity(),
                                rateLimitProperties.getLoginIp().getRefillPerSecond(),
                                ipCtx)) {
                        log.warn("Login blocked by IP rate limit. ip={}", ip);
                        throw new RateLimitExceededException("Too many login attempts");
                }

                Authentication authentication = authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(email, request.password()));

                SecurityContextHolder.getContext().setAuthentication(authentication);

                AuthPrincipal principal = (AuthPrincipal) authentication.getPrincipal();
                AuthLoginResult result = webAuthFacade.login(principal, response);

                log.info("Login successful. userId={} ip={}", principal.getUserId(), ip);

                return ResponseEntity.ok(
                                TokenResponse.of(
                                                result.accessToken(),
                                                jwtService.getAccessTtlSeconds(),
                                                result.user()));
        }

        @Operation(summary = "User registration", description = "Register a new user account. Sends email verification link. User must verify email before login.")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "201", description = "Registration successful, verification email sent"),
                        @ApiResponse(responseCode = "400", description = "Validation error or invalid input"),
                        @ApiResponse(responseCode = "409", description = "Email already exists")
        })
        @AuthAudit(event = AuthAuditEvent.REGISTER, subject = AuditSubjectType.EMAIL, subjectParam = "request")
        @PostMapping("/register")
        public ResponseEntity<Map<String, String>> register(
                        @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "User registration details", required = true) @RequestBody @Valid UserCreateRequest request) {
                authService.register(request);
                return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                                "message", "Registration successful. Please verify your email.",
                                "status", "success"));
        }

        /* ===================== EMAIL VERIFICATION ===================== */

        @Operation(summary = "Verify email address", description = "Verify user email address using the token sent via email during registration.")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Email verified successfully"),
                        @ApiResponse(responseCode = "400", description = "Invalid or expired verification token"),
                        @ApiResponse(responseCode = "409", description = "Email already verified")
        })
        @AuthAudit(event = AuthAuditEvent.EMAIL_VERIFICATION, subject = AuditSubjectType.SYSTEM)
        @GetMapping("/email-verify")
        public ResponseEntity<Map<String, String>> verifyEmail(
                        @Parameter(description = "Email verification token (UUID format)", required = true) @RequestParam @NotBlank @Pattern(regexp = "^[0-9a-fA-F\\-]{36}$", message = "Invalid verification token format") String token) {
                authService.verifyEmail(token);
                return ResponseEntity.ok(Map.of(
                                "message", "Email verified successfully.",
                                "status", "success"));
        }

        @Operation(summary = "Resend verification email", description = "Resend email verification link. Always returns success to prevent user enumeration.")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "If email exists, verification link has been sent")
        })
        @AuthAudit(event = AuthAuditEvent.EMAIL_VERIFICATION_RESEND, subject = AuditSubjectType.EMAIL, subjectParam = "email")
        @PostMapping("/email-verify/resend")
        public ResponseEntity<Map<String, String>> resendVerification(
                        @Parameter(description = "Email address to resend verification to", required = true) @RequestParam @NotBlank String email) {
                log.debug("Resend verification requested");
                authService.resendVerification(email);

                // Always return success to avoid user enumeration
                return ResponseEntity.ok(Map.of(
                                "message", "If the email exists, a verification link has been sent.",
                                "status", "success"));
        }

        /* ===================== PASSWORD RESET ===================== */

        @Operation(summary = "Initiate password reset", description = "Request password reset email. Always returns success to prevent user enumeration.")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "If email exists, password reset link has been sent")
        })
        @AuthAudit(event = AuthAuditEvent.PASSWORD_RESET_REQUESTED, subject = AuditSubjectType.EMAIL, subjectParam = "request")
        @PostMapping("/forgot-password")
        public ResponseEntity<Map<String, String>> initiatePasswordReset(
                        @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Email address for password reset", required = true) @Valid @RequestBody PasswordResetRequest request) {
                log.debug("Password reset initiation requested");
                authService.initiatePasswordReset(request.email());

                // Always succeed to prevent user enumeration
                return ResponseEntity.ok(Map.of(
                                "message", "If the email exists, a password reset link has been sent.",
                                "status", "success"));
        }

        @Operation(summary = "Confirm password reset", description = "Reset password using the token sent via email.")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Password reset successful"),
                        @ApiResponse(responseCode = "400", description = "Invalid or expired reset token"),
                        @ApiResponse(responseCode = "422", description = "Password does not meet policy requirements")
        })
        @AuthAudit(event = AuthAuditEvent.PASSWORD_RESET, subject = AuditSubjectType.SYSTEM)
        @PostMapping("/password-reset/confirm")
        public ResponseEntity<Map<String, String>> resetPassword(
                        @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Password reset confirmation with token and new password", required = true) @Valid @RequestBody ConfirmPasswordRequest request) {
                authService.resetPassword(request.token(), request.newPassword());

                return ResponseEntity.ok(Map.of(
                                "message", "Password reset successful.",
                                "status", "success"));
        }

        @Operation(summary = "Refresh access token", description = "Obtain a new access token using the refresh token cookie. The refresh token is automatically rotated for security.", security = @SecurityRequirement(name = "cookieAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Token refreshed successfully", content = @Content(schema = @Schema(implementation = TokenResponse.class))),
                        @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token"),
                        @ApiResponse(responseCode = "403", description = "Refresh token revoked or reuse detected")
        })
        @AuthAudit(event = AuthAuditEvent.TOKEN_REFRESH, subject = AuditSubjectType.USER_ID)
        @PostMapping("/refresh")
        public ResponseEntity<TokenResponse> refresh(
                        @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Optional refresh token in request body (if not using cookie)", required = false) @RequestBody(required = false) RefreshTokenRequest request,
                        HttpServletRequest httpRequest,
                        HttpServletResponse response) {
                final String ip = RequestIpResolver.resolve(httpRequest);

                log.debug("Refresh endpoint called | ip={}", ip);

                AuthLoginResult result = webAuthFacade.refresh(
                                httpRequest,
                                response,
                                request);

                log.info(
                                "Token refresh successful | userId={} ip={}",
                                result.user().id(),
                                ip);

                return ResponseEntity.ok(
                                TokenResponse.of(
                                                result.accessToken(),
                                                jwtService.getAccessTtlSeconds(),
                                                result.user()));
        }

        @Operation(summary = "User logout", description = "Logout current user session. Revokes refresh token and clears authentication cookies.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Logout successful"),
                        @ApiResponse(responseCode = "401", description = "Not authenticated")
        })
        @AuthAudit(event = AuthAuditEvent.LOGOUT_SINGLE_SESSION, subject = AuditSubjectType.USER_ID, subjectParam = "principal")
        @PostMapping("/logout")
        public ResponseEntity<Map<String, String>> logout(
                        @Parameter(hidden = true) @AuthenticationPrincipal AuthPrincipal principal,
                        HttpServletRequest request,
                        HttpServletResponse response) {
                webAuthFacade.logout(principal, request, response);
                SecurityContextHolder.clearContext();

                log.info(
                                "Logout successful. userId={} ip={}",
                                principal != null ? principal.getUserId() : "anonymous",
                                RequestIpResolver.resolve(request));

                return ResponseEntity.ok(Map.of(
                                "message", "Logout successful.",
                                "status", "success"));
        }

}
