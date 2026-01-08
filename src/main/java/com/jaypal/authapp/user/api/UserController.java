package com.jaypal.authapp.user.api;

import com.jaypal.authapp.user.dto.UserResponseDto;
import com.jaypal.authapp.user.dto.UserUpdateRequest;
import com.jaypal.authapp.user.application.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PutMapping("/{userId}")
    public ResponseEntity<UserResponseDto> updateUserDetails(@PathVariable String userId,
                                                             @Valid @RequestBody UserUpdateRequest userUpdateRequest) {
        UserResponseDto updatedUser = userService.updateUser(userId, userUpdateRequest);
        return ResponseEntity.status(HttpStatus.OK).body(updatedUser);
    }

}
