package com.jaypal.authapp.config;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties(prefix = "security.jwt")
@Getter
@Setter
@Validated
public class JwtCookieProperties {

    @NotBlank
    private String refreshTokenCookieName;

    private boolean cookieHttpOnly = true;

    private boolean cookieSecure = true;

    /**
     * Optional.
     * Leave empty to use current domain.
     */
    private String cookieDomain;

    /**
     * Allowed values: Strict, Lax, None
     */
    @NotBlank
    private String cookieSameSite;
}
