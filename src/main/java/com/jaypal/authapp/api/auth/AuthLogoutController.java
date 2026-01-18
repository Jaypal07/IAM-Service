package com.jaypal.authapp.api.auth;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.audit.entity.AuthProvider;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.service.auth.AuthService;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthLogoutController {

    private final AuthService authService;

    @AuthAudit(
            event = AuthAuditEvent.LOGOUT_ALL_SESSIONS,
            subject = AuditSubjectType.USER_ID,
            subjectParam = "principal",
            provider = AuthProvider.SYSTEM
    )
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
        if (principal == null) {
            log.warn("Logout-all called without authenticated principal");
            return ResponseEntity.status(401).build();
        }

        authService.logoutAllSessions(principal.getUserId());

        return ResponseEntity.noContent().build();
    }
}
