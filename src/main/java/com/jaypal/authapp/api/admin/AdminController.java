package com.jaypal.authapp.api.admin;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.user.service.AdminUserService;
import com.jaypal.authapp.dto.user.AdminUserCreateRequest;
import com.jaypal.authapp.dto.user.AdminUserRoleUpdateRequest;
import com.jaypal.authapp.dto.user.UserResponseDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Tag(name = "Admin - User Management", description = "Administrative endpoints for managing users, roles, and permissions. Requires ADMIN role.")
@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {

        private final AdminUserService adminUserService;

        @Operation(summary = "Create new user (Admin)", description = "Create a new user account with specific roles. Requires ADMIN role.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "201", description = "User created successfully", content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
                        @ApiResponse(responseCode = "400", description = "Validation error"),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions"),
                        @ApiResponse(responseCode = "409", description = "Email already exists")
        })
        @AuthAudit(event = AuthAuditEvent.ADMIN_USER_CREATED, subject = AuditSubjectType.USER_ID)
        @PostMapping
        public ResponseEntity<UserResponseDto> createUser(
                        @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "User creation details including roles", required = true) @RequestBody @Valid AdminUserCreateRequest request) {
                UserResponseDto user = adminUserService.createUser(request);
                log.info("Admin created user. userId={}", user.id());
                return ResponseEntity.status(HttpStatus.CREATED).body(user);
        }

        @Operation(summary = "Get user by ID (Admin)", description = "Retrieve user details by user ID. Requires ADMIN role.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "User found", content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions"),
                        @ApiResponse(responseCode = "404", description = "User not found")
        })
        @AuthAudit(event = AuthAuditEvent.ADMIN_USER_VIEWED, subject = AuditSubjectType.USER_ID, subjectParam = "userId")
        @GetMapping("/{userId}")
        public ResponseEntity<UserResponseDto> getUser(
                        @Parameter(description = "User ID", required = true) @PathVariable UUID userId) {
                return ResponseEntity.ok(adminUserService.getUserById(userId));
        }

        @Operation(summary = "Get user by email (Admin)", description = "Retrieve user details by email address. Requires ADMIN role.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "User found", content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions"),
                        @ApiResponse(responseCode = "404", description = "User not found")
        })
        @AuthAudit(event = AuthAuditEvent.ADMIN_USER_VIEWED, subject = AuditSubjectType.EMAIL, subjectParam = "email")
        @GetMapping("/by-email")
        public ResponseEntity<UserResponseDto> getUserByEmail(
                        @Parameter(description = "User email address", required = true) @RequestParam @Email @Size(max = 100) String email) {
                return ResponseEntity.ok(adminUserService.getUserByEmail(email));
        }

        @Operation(summary = "List all users (Admin)", description = "Retrieve a list of all users in the system. Requires ADMIN role.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
        })
        @AuthAudit(event = AuthAuditEvent.ADMIN_USER_LISTED, subject = AuditSubjectType.SYSTEM)
        @GetMapping
        public ResponseEntity<List<UserResponseDto>> getAllUsers() {
                return ResponseEntity.ok(adminUserService.getAllUsers());
        }

        @Operation(summary = "Update user roles (Admin)", description = "Update the roles assigned to a user. Requires ADMIN role.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "User roles updated successfully", content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
                        @ApiResponse(responseCode = "400", description = "Validation error or invalid role operation"),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions"),
                        @ApiResponse(responseCode = "404", description = "User not found")
        })
        @AuthAudit(event = AuthAuditEvent.ADMIN_ROLE_MODIFIED, subject = AuditSubjectType.USER_ID, subjectParam = "userId")
        @PutMapping("/{userId}/roles")
        public ResponseEntity<UserResponseDto> updateUserRoles(
                        @Parameter(description = "User ID", required = true) @PathVariable UUID userId,
                        @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Updated role assignments", required = true) @RequestBody @Valid AdminUserRoleUpdateRequest request) {
                UserResponseDto user = adminUserService.updateUserRoles(userId, request);

                log.info("Admin updated user roles. userId={}", userId);
                return ResponseEntity.ok(user);
        }

        @Operation(summary = "Disable user account (Admin)", description = "Disable a user account. Disabled users cannot log in. Requires ADMIN role.", security = @SecurityRequirement(name = "bearerAuth"))
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "User disabled successfully"),
                        @ApiResponse(responseCode = "401", description = "Not authenticated"),
                        @ApiResponse(responseCode = "403", description = "Insufficient permissions"),
                        @ApiResponse(responseCode = "404", description = "User not found")
        })
        @AuthAudit(event = AuthAuditEvent.ADMIN_USER_DELETED, subject = AuditSubjectType.USER_ID, subjectParam = "userId")
        @DeleteMapping("/{userId}")
        public ResponseEntity<Map<String, Serializable>> disableUser(
                        @Parameter(description = "User ID", required = true) @PathVariable UUID userId) {
                adminUserService.disableUser(userId);

                log.info("Admin disabled user. userId={}", userId);

                return ResponseEntity.ok(Map.of(
                                "message", "User disabled successfully",
                                "userId", userId));
        }

}
