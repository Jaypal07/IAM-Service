package com.jaypal.authapp.user.api;

import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.application.UserService;
import com.jaypal.authapp.user.dto.UserResponseDto;
import com.jaypal.authapp.user.dto.UserUpdateRequest;
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

