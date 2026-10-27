package com.example.rbacauth.auth;

public record AuthResponse(String accessToken, String tokenType, long expiresIn) {
}
