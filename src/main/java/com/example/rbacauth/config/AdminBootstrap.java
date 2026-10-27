package com.example.rbacauth.config;

import com.example.rbacauth.user.AppUser;
import com.example.rbacauth.user.AppUserRepository;
import com.example.rbacauth.user.Role;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class AdminBootstrap implements ApplicationRunner {

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final String username;
    private final String password;

    public AdminBootstrap(AppUserRepository users, PasswordEncoder passwordEncoder,
                         @Value("${app.bootstrap-admin.username:}") String username,
                         @Value("${app.bootstrap-admin.password:}") String password) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.username = username;
        this.password = password;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (username.isBlank() && password.isBlank()) {
            return;
        }
        String normalizedUsername = username.trim().toLowerCase(java.util.Locale.ROOT);
        if (normalizedUsername.length() < 3 || normalizedUsername.length() > 64
                || !normalizedUsername.matches("[A-Za-z0-9._-]+")
                || password.isBlank() || password.length() < 12
                || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalStateException("ADMIN_USERNAME must be 3-64 valid characters and ADMIN_PASSWORD must be 12-72 UTF-8 bytes.");
        }
        if (users.existsByUsername(normalizedUsername)) {
            return;
        }
        users.save(new AppUser(normalizedUsername, passwordEncoder.encode(password), Set.of(Role.ADMIN)));
    }
}
