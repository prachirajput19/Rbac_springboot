package com.example.rbacauth.auth;

import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/health")
    public HealthResponse health() {
        return new HealthResponse("UP");
    }

    @GetMapping("/users/me")
    public UserProfile currentUser(@AuthenticationPrincipal Jwt jwt) {
        return new UserProfile(jwt.getSubject(), jwt.getClaimAsStringList("roles"));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public AdminResponse admin() {
        return new AdminResponse("You have administrator access.");
    }

    public record HealthResponse(String status) {
    }

    public record UserProfile(String username, List<String> roles) {
    }

    public record AdminResponse(String message) {
    }
}
