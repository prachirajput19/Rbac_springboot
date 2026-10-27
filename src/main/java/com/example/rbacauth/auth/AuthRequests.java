package com.example.rbacauth.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class AuthRequests {

    private AuthRequests() {
    }

    public record Register(
            @NotBlank
            @Size(min = 3, max = 64)
            @Pattern(regexp = "[A-Za-z0-9._-]+", message = "must contain only letters, numbers, dots, underscores, or hyphens")
            String username,
            @NotBlank
            @Size(min = 12, max = 72)
            String password) {
    }

    public record Login(
            @NotBlank
            String username,
            @NotBlank
            String password) {
    }
}
