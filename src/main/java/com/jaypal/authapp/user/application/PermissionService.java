package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;

    @Transactional(readOnly = true)
    public Set<PermissionType> resolvePermissions(UUID userId) {
        return permissionRepository.findPermissionTypesByUserId(userId);
    }

    public String permissionHash(Set<PermissionType> permissions) {
        return permissions.stream()
                .map(Enum::name)
                .sorted()
                .collect(Collectors.joining("|"));
    }

}
