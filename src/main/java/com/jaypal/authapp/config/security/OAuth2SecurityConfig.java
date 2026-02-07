package com.jaypal.authapp.config.security;

import com.jaypal.authapp.config.security.entrypoint.OAuth2AuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@RequiredArgsConstructor
@Order(1)
@ConditionalOnProperty(prefix = "spring.security.oauth2.client.registration.google", name = "client-id")
public class OAuth2SecurityConfig {

        private final AuthenticationSuccessHandler successHandler;
        private final AuthenticationFailureHandler failureHandler;
        private final OAuth2AuthenticationEntryPoint authenticationEntryPoint;

        @Bean
        public SecurityFilterChain oauthSecurityFilterChain(HttpSecurity http) throws Exception {
                http
                        .securityMatcher("/api/v1/oauth2/authorization/**",
                                "/oauth2/authorization/**",
                                "/login/oauth2/code/**")
                        .csrf(AbstractHttpConfigurer::disable)
                        .cors(Customizer.withDefaults())
                        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                        .oauth2Login(oauth -> oauth
                        .successHandler(successHandler)
                        .failureHandler(failureHandler))
                        .exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint));

                return http.build();
        }
}
