package com.jaypal.authapp.domain.user.service;

import com.jaypal.authapp.config.properties.PasswordPolicy;
import com.jaypal.authapp.domain.dto.user.UserCreateRequest;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class InternalUserServiceImpl implements InternalUserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final UserProvisioningService userProvisioningService;

    @Override
    @Transactional
    public User createAndReturnDomainUser(UserCreateRequest req) {
        passwordPolicy.validate(req.password());

        User user = User.createLocal(
                req.email(),
                passwordEncoder.encode(req.password()),
                req.name()
        );

        User saved = userRepository.save(user);
        userProvisioningService.provisionNewUser(saved);
        return saved;
    }
}

