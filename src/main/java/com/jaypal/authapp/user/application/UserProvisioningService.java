package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.model.RoleType;
import com.jaypal.authapp.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserProvisioningService {

    private final UserRoleService userRoleService;

    /**
     * Apply default IAM rules to a newly created user.
     * Safe to call multiple times.
     */
    @Transactional
    public void provisionNewUser(User user) {
        ensureDefaultRole(user);
    }

    private void ensureDefaultRole(User user) {
        if (user.getRoles().isEmpty()) {
            log.info("Assigning default ROLE_USER. userId={}", user.getId());
            userRoleService.assignRole(user, RoleType.ROLE_USER);
        }
    }
}
