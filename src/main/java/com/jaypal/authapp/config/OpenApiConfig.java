package com.jaypal.authapp.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI/Swagger configuration for production-grade API documentation.
 * Configures security schemes, API metadata, and server information.
 */
@Configuration
public class OpenApiConfig {

        @Value("${app.frontend.base-url:http://localhost:3000}")
        private String frontendUrl;

        @Value("${server.port:8080}")
        private String serverPort;

        private static final String SECURITY_SCHEME_BEARER = "bearerAuth";
        private static final String SECURITY_SCHEME_COOKIE = "cookieAuth";

        @Bean
        public OpenAPI customOpenAPI() {
                return new OpenAPI()
                                .info(apiInfo())
                                .servers(serverList())
                                .components(securityComponents())
                                .addSecurityItem(new SecurityRequirement()
                                                .addList(SECURITY_SCHEME_BEARER)
                                                .addList(SECURITY_SCHEME_COOKIE));
        }

        /**
         * API metadata information
         */
        private Info apiInfo() {
                return new Info()
                                .title("Scalable Identity & Access Management (IAM) API")
                                .description("""
                                                **Production-Grade Authentication & Authorization Service**

                                                This API provides comprehensive identity and access management capabilities including:
                                                - Email/Password authentication with JWT tokens
                                                - OAuth2 social login (Google, GitHub)
                                                - Email verification and password reset flows
                                                - Role-based access control (RBAC)
                                                - Token refresh with rotation and replay detection
                                                - Rate limiting and abuse prevention
                                                - Comprehensive audit logging

                                                ## Authentication

                                                Most endpoints require authentication using JWT Bearer tokens:
                                                1. Login via `/api/v1/auth/login` to obtain an access token
                                                2. Include the token in the `Authorization` header: `Bearer <token>`
                                                3. Access tokens expire after 15 minutes
                                                4. Use `/api/v1/auth/refresh` to obtain a new access token using the refresh cookie

                                                ## Security

                                                - All authentication endpoints are rate-limited
                                                - Passwords are hashed using BCrypt
                                                - Refresh tokens are rotated on every use
                                                - Tokens are stored securely with optimistic locking
                                                - CORS and CSRF protection are enabled

                                                ## Error Handling

                                                All error responses follow a consistent format with:
                                                - HTTP status code
                                                - Error message
                                                - Timestamp
                                                - Request path
                                                """)
                                .version("1.0.0")
                                .contact(new Contact()
                                                .name("Jaypal Koli")
                                                .url("https://github.com/Jaypal07")
                                                .email("kolijaypal77@gmail.com"))
                                .license(new License()
                                                .name("MIT License")
                                                .url("https://opensource.org/licenses/MIT"));
        }

        /**
         * Server configuration for different environments
         */
        private List<Server> serverList() {
                Server localServer = new Server()
                                .url("http://localhost:" + serverPort)
                                .description("Local Development Server");

                return List.of(localServer);
        }

        /**
         * Security scheme components for JWT and Cookie authentication
         */
        private Components securityComponents() {
                return new Components()
                                .addSecuritySchemes(SECURITY_SCHEME_BEARER,
                                                new SecurityScheme()
                                                                .type(SecurityScheme.Type.HTTP)
                                                                .scheme("bearer")
                                                                .bearerFormat("JWT")
                                                                .in(SecurityScheme.In.HEADER)
                                                                .name("Authorization")
                                                                .description(
                                                                                "JWT Bearer token obtained from /api/v1/auth/login or /api/v1/auth/refresh"))
                                .addSecuritySchemes(SECURITY_SCHEME_COOKIE,
                                                new SecurityScheme()
                                                                .type(SecurityScheme.Type.APIKEY)
                                                                .in(SecurityScheme.In.COOKIE)
                                                                .name("refreshToken")
                                                                .description("HTTP-only refresh token cookie automatically sent by browser"));
        }
}
