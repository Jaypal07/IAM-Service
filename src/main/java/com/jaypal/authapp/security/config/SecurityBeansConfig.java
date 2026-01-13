package com.jaypal.authapp.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.jaypal.authapp.config.FrontendProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class SecurityBeansConfig {

    private static final int BCRYPT_STRENGTH = 12;
    private static final List<String> ALLOWED_HTTP_METHODS = List.of(
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
    );
    private static final long CORS_MAX_AGE_SECONDS = 3600L;

    private final FrontendProperties frontendProperties;

    @PostConstruct
    public void validateConfiguration() {
        final String frontendUrl = frontendProperties.getBaseUrl();

        if (frontendUrl == null || frontendUrl.isBlank()) {
            throw new IllegalStateException(
                    "Frontend base URL is missing. Set 'app.frontend.base-url' in configuration."
            );
        }

        try {
            new URL(frontendUrl);
        } catch (MalformedURLException ex) {
            throw new IllegalStateException(
                    "Frontend base URL is invalid: " + frontendUrl, ex
            );
        }

        log.info("Security configuration validated - Frontend URL: {}", frontendUrl);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(BCRYPT_STRENGTH);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration
    ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of(frontendProperties.getBaseUrl()));
        config.setAllowedMethods(ALLOWED_HTTP_METHODS);
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(CORS_MAX_AGE_SECONDS);
        config.setExposedHeaders(List.of("Authorization", "X-Total-Count"));

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        log.info("CORS configured for origin: {}", frontendProperties.getBaseUrl());

        return source;
    }

    @Bean
    public ObjectMapper objectMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.findAndRegisterModules();
        return mapper;
    }
}