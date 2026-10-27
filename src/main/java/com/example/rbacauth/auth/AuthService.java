package com.example.rbacauth.auth;

import com.example.rbacauth.api.ApiException;
import com.example.rbacauth.user.AppUser;
import com.example.rbacauth.user.AppUserRepository;
import com.example.rbacauth.user.Role;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(AppUserRepository users, PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager, TokenService tokenService,
                       RefreshTokenService refreshTokenService) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.refreshTokenService = refreshTokenService;
    }

    @Transactional
    public AuthenticatedTokens register(AuthRequests.Register request) {
        String username = normalizeUsername(request.username());
        validatePasswordBytes(request.password());
        if (users.existsByUsername(username)) {
            throw new ApiException(HttpStatus.CONFLICT, "Username is already registered.");
        }
        AppUser user = users.save(new AppUser(username, passwordEncoder.encode(request.password()),
                Set.of(Role.USER)));
        return issueTokens(user);
    }

    public AuthenticatedTokens login(AuthRequests.Login request) {
        String username = normalizeUsername(request.username());
        validatePasswordBytes(request.password());
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, request.password()));
        } catch (BadCredentialsException exception) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Username or password is incorrect.");
        }
        AppUser user = users.findByUsername(username)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Username or password is incorrect."));
        return issueTokens(user);
    }

    public AuthenticatedTokens refresh(String rawRefreshToken) {
        RefreshTokenService.IssuedToken refreshed = refreshTokenService.rotate(rawRefreshToken);
        AppUser user = users.findByUsername(refreshed.username())
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Refresh token is invalid or expired."));
        return new AuthenticatedTokens(tokenService.createAccessToken(user), refreshed.value());
    }

    public void logout(String rawRefreshToken) {
        refreshTokenService.revoke(rawRefreshToken);
    }

    private AuthenticatedTokens issueTokens(AppUser user) {
        RefreshTokenService.IssuedToken refreshToken = refreshTokenService.create(user);
        return new AuthenticatedTokens(tokenService.createAccessToken(user), refreshToken.value());
    }

    private static String normalizeUsername(String username) {
        return username.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static void validatePasswordBytes(String password) {
        if (password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Password must not exceed 72 UTF-8 bytes.");
        }
    }

    public record AuthenticatedTokens(String accessToken, String refreshToken) {
    }
}
