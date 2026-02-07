package com.jaypal.authapp.api.auth;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.audit.entity.AuthProvider;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.service.auth.AuthService;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Authentication", description = "Authentication and authorization endpoints for user login, registration, email verification, and password management")
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthLogoutController {

    private final AuthService authService;

    @Operation(summary = "Logout all sessions", description = "Revoke all refresh tokens for the current user across all devices and sessions. This will force re-authentication on all devices.", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "All sessions logged out successfully"),
            @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @AuthAudit(event = AuthAuditEvent.LOGOUT_ALL_SESSIONS, subject = AuditSubjectType.USER_ID, subjectParam = "principal", provider = AuthProvider.SYSTEM)
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(
            @Parameter(hidden = true) @AuthenticationPrincipal AuthPrincipal principal) {
        if (principal == null) {
            log.warn("Logout-all called without authenticated principal");
            return ResponseEntity.status(401).build();
        }

        authService.logoutAllSessions(principal.getUserId());

        return ResponseEntity.noContent().build();
    }
}
