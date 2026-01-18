package com.jaypal.authapp.mapper;

import com.jaypal.authapp.domain.user.entity.Provider;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

@Slf4j
public final class OAuthUserInfoMapperFactory {

    private OAuthUserInfoMapperFactory() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static OAuthUserInfoMapper get(Provider provider) {
        Objects.requireNonNull(provider, "OAuth provider cannot be null");

        return switch (provider) {
            case GOOGLE -> {
                log.debug("Creating Google OAuth user info mapper");
                yield new GoogleOAuthUserInfoMapper();
            }
            case GITHUB -> {
                log.debug("Creating GitHub OAuth user info mapper");
                yield new GithubOAuthUserInfoMapper();
            }
            case SYSTEM -> throw new IllegalArgumentException(
                    "SYSTEM provider is not valid for OAuth authentication");
        };
    }
}

/*
CHANGELOG:
1. Added private constructor that throws to prevent instantiation
2. Added null check for provider parameter
3. Added SYSTEM provider rejection (should not use OAuth mapper)
4. Added logging for debugging
5. Used yield in switch expression for clarity
6. Made error messages more descriptive
*/