package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.model.RoleType;
import com.jaypal.authapp.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserProvisioningService {

    private final UserRoleService userRoleService;

    /**
     * Apply default IAM rules to a newly created user.
     * Idempotent and safe for retries.
     */
    @Transactional
    public void provisionNewUser(User user) {
        Objects.requireNonNull(user, "User cannot be null");

        if (user.getRoles().isEmpty()) {
            log.info("Assigning default ROLE_USER. userId={}", user.getId());
            userRoleService.assignRoleInternal(user, RoleType.ROLE_USER);
        }
    }
}
