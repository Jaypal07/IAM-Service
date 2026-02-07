package com.jaypal.authapp.api.auth;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.audit.entity.AuthProvider;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.service.auth.TokenIntrospectionService;
import com.jaypal.authapp.dto.auth.TokenIntrospectionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Authentication", description = "Authentication and authorization endpoints for user login, registration, email verification, and password management")
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class TokenIntrospectionController {

    private final TokenIntrospectionService introspectionService;

    @Operation(summary = "Token introspection", description = "Introspect a JWT access token to check its validity and extract claims. Returns token status and metadata.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token introspection result", content = @Content(schema = @Schema(implementation = TokenIntrospectionResponse.class)))
    })
    @AuthAudit(event = AuthAuditEvent.TOKEN_INTROSPECTION, subject = AuditSubjectType.ANONYMOUS, provider = AuthProvider.SYSTEM)
    @PostMapping("/introspect")
    public TokenIntrospectionResponse introspect(
            @Parameter(description = "Bearer token in Authorization header", required = false) @RequestHeader(name = "Authorization", required = false) String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            log.debug("Token introspection called without bearer token");
            return TokenIntrospectionResponse.inactive();
        }

        return introspectionService.introspect(header.substring(7).trim());
    }
}
