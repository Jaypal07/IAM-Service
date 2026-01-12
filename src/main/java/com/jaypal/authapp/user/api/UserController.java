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
            return ResponseEntity.status(401).build();
        }

        UserResponseDto user =
                userService.getUserById(principal.getUserId());

        return ResponseEntity.ok(user);
    }

    @PutMapping("/me")
    public ResponseEntity<UserResponseDto> updateCurrentUser(
            @AuthenticationPrincipal AuthPrincipal principal,
            @Valid @RequestBody UserUpdateRequest request
    ) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        UUID userId = principal.getUserId();

        UserResponseDto user =
                userService.updateSelf(userId, request);

        log.info("User updated own profile. userId={}", userId);

        return ResponseEntity.ok(user);
    }

    @DeleteMapping("/me")
    public ResponseEntity<Void> deleteCurrentUser(
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        UUID userId = principal.getUserId();

        userService.deleteSelf(userId);

        log.info("User deleted own account. userId={}", userId);

        return ResponseEntity.noContent().build();
    }
}
