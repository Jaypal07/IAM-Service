package com.jaypal.authapp.api.user;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.domain.user.service.UserService;
import com.jaypal.authapp.dto.user.UserResponseDto;
import com.jaypal.authapp.dto.user.UserUpdateRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Tag(name = "User Profile", description = "User profile management endpoints for viewing, updating, and deleting user accounts")
@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(summary = "Get current user profile", description = "Retrieve the profile information of the currently authenticated user.", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User profile retrieved successfully", content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
            @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @AuthAudit(event = AuthAuditEvent.ACCOUNT_VIEWED_SELF, subject = AuditSubjectType.USER_ID)
    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> getCurrentUser(
            @Parameter(hidden = true) @AuthenticationPrincipal AuthPrincipal principal) {
        if (principal == null) {
            log.debug("Unauthenticated request to GET /users/me");
            return ResponseEntity.status(401).build();
        }

        UUID userId = principal.getUserId();
        log.debug("Fetching self profile. userId={}", userId);

        return ResponseEntity.ok(userService.getSelf(userId));
    }

    @Operation(summary = "Update current user profile", description = "Update the profile information of the currently authenticated user.", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User profile updated successfully", content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
            @ApiResponse(responseCode = "400", description = "Validation error"),
            @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @AuthAudit(event = AuthAuditEvent.ACCOUNT_UPDATED_SELF, subject = AuditSubjectType.USER_ID)
    @PutMapping("/me")
    public ResponseEntity<UserResponseDto> updateCurrentUser(
            @Parameter(hidden = true) @AuthenticationPrincipal AuthPrincipal principal,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Updated user profile information", required = true) @Valid @RequestBody UserUpdateRequest request) {
        if (principal == null) {
            log.debug("Unauthenticated request to PUT /users/me");
            return ResponseEntity.status(401).build();
        }

        UUID userId = principal.getUserId();
        log.debug("Updating self profile. userId={}", userId);

        UserResponseDto user = userService.updateSelf(userId, request);

        log.info("User updated own profile. userId={}", userId);
        return ResponseEntity.ok(user);
    }

    @Operation(summary = "Delete current user account", description = "Delete the account of the currently authenticated user. This action cannot be undone.", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "User account deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @AuthAudit(event = AuthAuditEvent.ACCOUNT_UPDATED_SELF, subject = AuditSubjectType.USER_ID)
    @DeleteMapping("/me")
    public ResponseEntity<Void> deleteCurrentUser(
            @Parameter(hidden = true) @AuthenticationPrincipal AuthPrincipal principal) {
        if (principal == null) {
            log.debug("Unauthenticated request to DELETE /users/me");
            return ResponseEntity.status(401).build();
        }

        UUID userId = principal.getUserId();
        log.warn("User requested self delete. userId={}", userId);

        userService.deleteSelf(userId);
        return ResponseEntity.noContent().build();
    }
}
