package com.jaypal.authapp.services;

import com.jaypal.authapp.dto.UserDto;

public interface AuthService {
    UserDto registerUser(UserDto userDto);
}
