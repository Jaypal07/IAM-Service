package com.jaypal.authapp.service.oauth.operations;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.jaypal.authapp.domain.user.entity.Provider;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.domain.user.service.UserProvisioningService;
import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;

import lombok.RequiredArgsConstructor;

/**
 * Resolves OAuth user in an atomic way.
 * Responsibility: find OR create user + provision roles in same TX.
 */
@Component
@RequiredArgsConstructor
public class OAuthUserResolver {

    private final UserRepository userRepository;
    private final UserProvisioningService provisioningService;

    @Transactional
    public User resolveOrCreate(Provider provider, ValidatedOAuthUserInfo info) {

        return userRepository.findByProviderAndProviderId(provider, info.providerId())
                .or(() -> userRepository.findByEmail(info.email()))
                .orElseGet(() -> create(provider, info));
    }

    private User create(Provider provider, ValidatedOAuthUserInfo info) {
        try {
            User user = User.createOAuth(
                    provider,
                    info.providerId(),
                    info.email(),
                    info.name(),
                    info.image()
            );

            userRepository.save(user);

            // Assign default roles immediately in same TX
            provisioningService.provisionNewUser(user);

            return user;

        } catch (DataIntegrityViolationException ex) {
            // Handle concurrent creation safely
            return userRepository.findByProviderAndProviderId(provider, info.providerId())
                    .orElseThrow(() ->
                            new IllegalStateException("OAuth user creation race condition", ex)
                    );
        }
    }
}
