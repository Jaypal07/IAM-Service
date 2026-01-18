package com.jaypal.authapp.api.user;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.domain.user.service.UserService;
import com.jaypal.authapp.dto.user.UserResponseDto;
import com.jaypal.authapp.dto.user.UserUpdateRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @AuthAudit(
            event = AuthAuditEvent.ACCOUNT_VIEWED_SELF,
            subject = AuditSubjectType.USER_ID
    )
    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> getCurrentUser(
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
        if (principal == null) {
            log.debug("Unauthenticated request to GET /users/me");
            return ResponseEntity.status(401).build();
        }

        UUID userId = principal.getUserId();
        log.debug("Fetching self profile. userId={}", userId);

        return ResponseEntity.ok(userService.getSelf(userId));
    }

    @AuthAudit(
            event = AuthAuditEvent.ACCOUNT_UPDATED_SELF,
            subject = AuditSubjectType.USER_ID
    )
    @PutMapping("/me")
    public ResponseEntity<UserResponseDto> updateCurrentUser(
            @AuthenticationPrincipal AuthPrincipal principal,
            @Valid @RequestBody UserUpdateRequest request
    ) {
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

    @AuthAudit(
            event = AuthAuditEvent.ACCOUNT_UPDATED_SELF,
            subject = AuditSubjectType.USER_ID
    )
    @DeleteMapping("/me")
    public ResponseEntity<Void> deleteCurrentUser(
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
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

