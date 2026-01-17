package com.jaypal.authapp.security.ratelimit;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin/rate-limit")
@RequiredArgsConstructor
public class RateLimitAdminController {

    private final RateLimitAdminService adminService;

    @PostMapping("/reset/login/ip")
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    @AuthAudit(
            event = AuthAuditEvent.ADMIN_ACTION,
            subject = AuditSubjectType.IP
    )
    public ResponseEntity<Void> resetLoginIp(
            @RequestParam @NotBlank String ip
    ) {
        adminService.resetLoginIp(ip);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset/login/email")
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    public ResponseEntity<Void> resetLoginEmail(
            @RequestParam @Email String email
    ) {
        adminService.resetLoginEmail(email);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset/ip/all")
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    public ResponseEntity<Void> resetAllIp(
            @RequestParam @NotBlank String ip
    ) {
        adminService.resetAllIpLimits(ip);
        return ResponseEntity.noContent().build();
    }
}
