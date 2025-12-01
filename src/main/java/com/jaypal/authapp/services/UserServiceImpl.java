package com.jaypal.authapp.services;

import com.jaypal.authapp.dtos.UserDto;
import com.jaypal.authapp.entities.Provider;
import com.jaypal.authapp.entities.User;
import com.jaypal.authapp.exceptions.ResourceNotFoundExceptions;
import com.jaypal.authapp.helpers.UserHelper;
import com.jaypal.authapp.repositories.UserRepository;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {

        if(userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }
        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        User user = modelMapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL);
        //TODO:  assign new role to user

        User savedUser = userRepository.save(user);

        return modelMapper.map(savedUser, UserDto.class)
                ;
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundExceptions("User not found with given email id"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto, String userId) {

        UUID uId = UserHelper.parseUUID(userId);

        User userInDb = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundExceptions("User not found with ID: " + userId));
        // We assume email should not be changeable
        // if(userDto.getEmail() != null) userInDb.setEmail(userDto.getEmail());
        if (userDto.getName() != null) {
            userInDb.setName(userDto.getName());
        }
        if (userDto.getImage() != null) {
            userInDb.setImage(userDto.getImage());
        }
        if (userDto.getProvider() != null) {
            userInDb.setProvider(userDto.getProvider());
        }
        //TODO: change password update logic
        if (userDto.getPassword() != null) userInDb.setPassword(userDto.getPassword());

        userInDb.setEnabled(userDto.isEnabled());
        userInDb.setUpdatedAt(Instant.now());
        User savedUser = userRepository.save(userInDb);

        return modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundExceptions("User not found with given user id"));
        userRepository.delete(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto getUserById(String userId) {
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundExceptions("User not found with given user id"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional(readOnly = true)
    public Iterable<UserDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(user->modelMapper.map(user, UserDto.class))
                .toList();
    }
}
