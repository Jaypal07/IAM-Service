package com.jaypal.authapp.user.controller;

import com.jaypal.authapp.dto.AdminUserUpdateRequest;
import com.jaypal.authapp.dto.UserCreateRequest;
import com.jaypal.authapp.dto.UserResponseDto;
import com.jaypal.authapp.user.application.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<UserResponseDto> create(
            @RequestBody @Valid UserCreateRequest req

    ) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(userService.createUser(req));
    }

    @GetMapping
    public List<UserResponseDto> all() {
        return userService.getAllUsers();
    }

    @GetMapping("/{id}")
    public UserResponseDto get(@PathVariable String id) {
        return userService.getUserById(id);
    }

    @PutMapping("/{id}")
    public UserResponseDto adminUpdate(
            @PathVariable String id,
            @RequestBody AdminUserUpdateRequest req
    ) {
        return userService.adminUpdateUser(id, req);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

}
