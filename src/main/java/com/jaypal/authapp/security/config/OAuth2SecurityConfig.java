package com.jaypal.authapp.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
@Order(1)
@ConditionalOnProperty(
        prefix = "spring.security.oauth2.client.registration.google",
        name = "client-id"
)
public class OAuth2SecurityConfig {

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final ObjectMapper objectMapper;

    @Bean
    public SecurityFilterChain oauthSecurityFilterChain(HttpSecurity http)
            throws Exception {

        http
                .securityMatcher(
                        "/oauth2/**",
                        "/login/oauth2/**"
                )
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth ->
                        auth.anyRequest().authenticated()
                )
                .oauth2Login(oauth ->
                        oauth
                                .successHandler(successHandler)
                                .failureHandler(failureHandler)
                )
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(this::handleUnauthorized)
                );

        return http.build();
    }

    private void handleUnauthorized(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) {
        try {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");

            Map<String, String> error = Map.of(
                    "message", "OAuth authentication failed",
                    "statusCode", "401"
            );

            response.getWriter()
                    .write(objectMapper.writeValueAsString(error));

        } catch (Exception ex) {
            log.error("OAuth unauthorized response failed", ex);
        }
    }
}
