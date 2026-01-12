package com.jaypal.authapp.user.api;

import com.jaypal.authapp.user.dto.AdminUserRoleUpdateRequest;
import com.jaypal.authapp.user.dto.AdminUserUpdateRequest;
import com.jaypal.authapp.user.dto.UserCreateRequest;
import com.jaypal.authapp.user.dto.UserResponseDto;
import com.jaypal.authapp.user.application.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;

    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @PostMapping
    public ResponseEntity<UserResponseDto> createUser(
            @RequestBody @Valid UserCreateRequest request
    ) {
        final UserResponseDto user = userService.createUser(request);

        log.info("Admin created user - ID: {}", user.id());

        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PreAuthorize("hasAuthority('USER_READ')")
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponseDto> getUser(@PathVariable UUID userId) {
        final UserResponseDto user = userService.getUserById(userId);
        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @PutMapping("/{userId}")
    public ResponseEntity<UserResponseDto> updateUser(
            @PathVariable UUID userId,
            @RequestBody @Valid AdminUserUpdateRequest request
    ) {
        final UserResponseDto user = userService.adminUpdateUser(userId, request);

        log.info("Admin updated user - ID: {}", userId);

        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasAuthority('USER_ROLE_ASSIGN')")
    @PutMapping("/{userId}/roles")
    public ResponseEntity<UserResponseDto> updateUserRoles(
            @PathVariable UUID userId,
            @RequestBody @Valid AdminUserRoleUpdateRequest request
    ) {
        final UserResponseDto user = userService.adminUpdateUserRoles(userId, request);

        log.info("Admin updated user roles - ID: {}", userId);

        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasAuthority('USER_DISABLE')")
    @DeleteMapping("/{userId}")
    public ResponseEntity<Map<String, Serializable>> deleteUser(@PathVariable UUID userId) {
        userService.deleteSelf(userId);

        log.info("Admin deleted user - ID: {}", userId);

        return ResponseEntity.ok(Map.of(
                "message", "User deleted successfully",
                "userId", userId
        ));
    }
}

/*
CHANGELOG:
1. CRITICAL: Added @PreAuthorize to ALL endpoints (was missing)
2. Removed @AuthAudit (should be in service layer, not controller)
3. Changed path from /api/v1/admin to /api/v1/admin/users (REST convention)
4. Added @Valid to AdminUserUpdateRequest and AdminUserRoleUpdateRequest
5. Added GET endpoint for retrieving user details
6. Added @Slf4j for logging
7. Added logging for all admin actions
8. Made delete return success message instead of 204
9. Made all methods return ResponseEntity for consistency
10. Renamed methods to be more descriptive (create -> createUser, etc.)
*/