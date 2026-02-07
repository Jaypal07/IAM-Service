package com.jaypal.authapp.api.admin;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitAdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Admin - Rate Limiting", description = "Administrative endpoints for managing rate limits. Requires RATE_LIMIT_RESET permission.")
@RestController
@RequestMapping("/api/v1/admin/rate-limit")
@RequiredArgsConstructor
public class RateLimitAdminController {

        private final RateLimitAdminService adminService;

        @Operation(summary = "Reset login rate limit by IP (Admin)", description = "Reset the login rate limit for a specific IP address. Requires RATE_LIMIT_RESET permission.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "204", description = "Rate limit reset successfully"),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
        })
        @PostMapping("/reset/login/ip")
        @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
        @AuthAudit(event = AuthAuditEvent.ADMIN_ACTION_GENERIC, subject = AuditSubjectType.IP, subjectParam = "ip")
        public ResponseEntity<Void> resetLoginIp(
                        @Parameter(description = "IP address to reset rate limit for", required = true) @RequestParam @NotBlank String ip) {
                adminService.resetLoginIp(ip);
                return ResponseEntity.noContent().build();
        }

        @Operation(summary = "Reset login rate limit by email (Admin)", description = "Reset the login rate limit for a specific email address. Requires RATE_LIMIT_RESET permission.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "204", description = "Rate limit reset successfully"),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
        })
        @AuthAudit(event = AuthAuditEvent.ADMIN_ACTION_GENERIC, subject = AuditSubjectType.EMAIL, subjectParam = "email")
        @PostMapping("/reset/login/email")
        @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
        public ResponseEntity<Void> resetLoginEmail(
                        @Parameter(description = "Email address to reset rate limit for", required = true) @RequestParam @Email String email) {
                adminService.resetLoginEmail(email);
                return ResponseEntity.noContent().build();
        }

        @Operation(summary = "Reset all rate limits by IP (Admin)", description = "Reset all rate limits for a specific IP address across all endpoints. Requires RATE_LIMIT_RESET permission.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "204", description = "All rate limits reset successfully"),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
        })
        @AuthAudit(event = AuthAuditEvent.ADMIN_ACTION_GENERIC, subject = AuditSubjectType.IP, subjectParam = "ip")
        @PostMapping("/reset/ip/all")
        @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
        public ResponseEntity<Void> resetAllIp(
                        @Parameter(description = "IP address to reset all rate limits for", required = true) @RequestParam @NotBlank String ip) {
                adminService.resetAllIpLimits(ip);
                return ResponseEntity.noContent().build();
        }
}
