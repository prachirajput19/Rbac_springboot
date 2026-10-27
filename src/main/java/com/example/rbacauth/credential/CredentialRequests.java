package com.example.rbacauth.credential;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class CredentialRequests {

    private CredentialRequests() {
    }

    public record Create(
            @NotBlank
            @Size(min = 2, max = 64)
            @Pattern(regexp = "[A-Za-z0-9._-]+", message = "must contain only letters, numbers, dots, underscores, or hyphens")
            String provider,
            @NotBlank
            @Size(max = 8192)
            String token) {
    }
}
