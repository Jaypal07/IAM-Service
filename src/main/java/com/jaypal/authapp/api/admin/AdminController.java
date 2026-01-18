package com.jaypal.authapp.api.admin;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.user.service.AdminUserService;
import com.jaypal.authapp.dto.user.AdminUserCreateRequest;
import com.jaypal.authapp.dto.user.AdminUserRoleUpdateRequest;
import com.jaypal.authapp.dto.user.UserResponseDto;
import com.jaypal.authapp.user.dto.*;
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

@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminUserService adminUserService;

    @AuthAudit(
            event = AuthAuditEvent.ADMIN_USER_CREATED,
            subject = AuditSubjectType.USER_ID
    )
    @PostMapping
    public ResponseEntity<UserResponseDto> createUser(
            @RequestBody @Valid AdminUserCreateRequest request
    ) {
        UserResponseDto user = adminUserService.createUser(request);
        log.info("Admin created user. userId={}", user.id());
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }


    @AuthAudit(
            event = AuthAuditEvent.ADMIN_USER_VIEWED,
            subject = AuditSubjectType.USER_ID,
            subjectParam = "userId"
    )
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponseDto> getUser(@PathVariable UUID userId) {
        return ResponseEntity.ok(adminUserService.getUserById(userId));
    }

    @AuthAudit(
            event = AuthAuditEvent.ADMIN_USER_VIEWED,
            subject = AuditSubjectType.EMAIL,
            subjectParam = "email"
    )
    @GetMapping("/by-email")
    public ResponseEntity<UserResponseDto> getUserByEmail(
            @RequestParam
            @Email
            @Size(max = 100)
            String email
    ) {
        return ResponseEntity.ok(adminUserService.getUserByEmail(email));
    }

    @AuthAudit(
            event = AuthAuditEvent.ADMIN_USER_LISTED,
            subject = AuditSubjectType.SYSTEM
    )
    @GetMapping
    public ResponseEntity<List<UserResponseDto>> getAllUsers() {
        return ResponseEntity.ok(adminUserService.getAllUsers());
    }

    @AuthAudit(
            event = AuthAuditEvent.ADMIN_ROLE_MODIFIED,
            subject = AuditSubjectType.USER_ID,
            subjectParam = "userId"
    )
    @PutMapping("/{userId}/roles")
    public ResponseEntity<UserResponseDto> updateUserRoles(
            @PathVariable UUID userId,
            @RequestBody @Valid AdminUserRoleUpdateRequest request
    ) {
        UserResponseDto user =
                adminUserService.updateUserRoles(userId, request);

        log.info("Admin updated user roles. userId={}", userId);
        return ResponseEntity.ok(user);
    }

    @AuthAudit(
            event = AuthAuditEvent.ADMIN_USER_DELETED,
            subject = AuditSubjectType.USER_ID,
            subjectParam = "userId"
    )
    @DeleteMapping("/{userId}")
    public ResponseEntity<Map<String, Serializable>> disableUser(
            @PathVariable UUID userId
    ) {
        adminUserService.disableUser(userId);

        log.info("Admin disabled user. userId={}", userId);

        return ResponseEntity.ok(Map.of(
                "message", "User disabled successfully",
                "userId", userId
        ));
    }

}
