package com.jaypal.authapp.oauth;

import com.jaypal.authapp.entity.Provider;

import java.util.Map;

public record OAuthUserInfo(
        String providerId,
        String email,
        String name,
        String image
) {

    public static OAuthUserInfo from(Provider provider, Map<String, Object> attrs) {

        return switch (provider) {

            case GOOGLE -> new OAuthUserInfo(
                    attrs.get("sub").toString(),
                    (String) attrs.get("email"),
                    (String) attrs.get("name"),
                    (String) attrs.get("picture")
            );

            case GITHUB -> new OAuthUserInfo(
                    attrs.get("id").toString(),
                    (String) attrs.get("email"), // may be null
                    (String) attrs.get("login"),
                    (String) attrs.get("avatar_url")
            );

            default -> throw new IllegalStateException("Unsupported OAuth provider");
        };
    }
}
