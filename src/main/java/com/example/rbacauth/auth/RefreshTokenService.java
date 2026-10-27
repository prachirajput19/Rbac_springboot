package com.example.rbacauth.auth;

import com.example.rbacauth.api.ApiException;
import com.example.rbacauth.user.AppUser;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository tokens;
    private final Duration refreshTokenTtl;

    public RefreshTokenService(RefreshTokenRepository tokens,
                               @Value("${app.refresh-token-ttl:PT168H}") Duration refreshTokenTtl) {
        if (refreshTokenTtl.isNegative() || refreshTokenTtl.isZero()) {
            throw new IllegalStateException("REFRESH_TOKEN_TTL must be a positive duration.");
        }
        this.tokens = tokens;
        this.refreshTokenTtl = refreshTokenTtl;
    }

    @Transactional
    public IssuedToken create(AppUser user) {
        String rawToken = newRawToken();
        String hash = hash(rawToken);
        tokens.save(new RefreshToken(hash, UUID.randomUUID().toString(), user.getUsername(),
                Instant.now().plus(refreshTokenTtl)));
        return new IssuedToken(rawToken, user.getUsername());
    }

    @Transactional(noRollbackFor = ApiException.class)
    public IssuedToken rotate(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw unauthorized();
        }
        String oldHash = hash(rawToken);
        RefreshToken current = tokens.findByTokenHashForUpdate(oldHash)
                .orElseThrow(RefreshTokenService::unauthorized);
        Instant now = Instant.now();

        if (current.getRevokedAt() != null) {
            tokens.revokeActiveFamily(current.getFamilyId(), now);
            throw unauthorized();
        }
        if (!current.getExpiresAt().isAfter(now)) {
            current.revoke(now, null);
            throw unauthorized();
        }

        String replacement = newRawToken();
        String replacementHash = hash(replacement);
        current.revoke(now, replacementHash);
        tokens.save(new RefreshToken(replacementHash, current.getFamilyId(), current.getUsername(),
                now.plus(refreshTokenTtl)));
        return new IssuedToken(replacement, current.getUsername());
    }

    @Transactional
    public void revoke(String rawToken) {
        if (rawToken != null && !rawToken.isBlank()) {
            tokens.revokeToken(hash(rawToken), Instant.now());
        }
    }

    public long ttlSeconds() {
        return refreshTokenTtl.toSeconds();
    }

    private static String newRawToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }

    private static ApiException unauthorized() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "Refresh token is invalid or expired.");
    }

    public record IssuedToken(String value, String username) {
    }
}
