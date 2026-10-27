package com.example.rbacauth.auth;

import com.example.rbacauth.user.AppUser;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final Duration accessTokenTtl;

    public TokenService(JwtEncoder jwtEncoder,
                        @Value("${app.jwt.access-token-ttl:PT15M}") Duration accessTokenTtl) {
        if (accessTokenTtl.isNegative() || accessTokenTtl.isZero()) {
            throw new IllegalStateException("ACCESS_TOKEN_TTL must be a positive duration.");
        }
        this.jwtEncoder = jwtEncoder;
        this.accessTokenTtl = accessTokenTtl;
    }

    public String createAccessToken(AppUser user) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("rbac-auth")
                .issuedAt(now)
                .expiresAt(now.plus(accessTokenTtl))
                .subject(user.getUsername())
                .claim("roles", user.getRoles().stream().map(Enum::name).sorted().toList())
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(
                org.springframework.security.oauth2.jwt.JwsHeader.with(MacAlgorithm.HS256).build(), claims))
                .getTokenValue();
    }

    public long accessTokenTtlSeconds() {
        return accessTokenTtl.toSeconds();
    }
}
