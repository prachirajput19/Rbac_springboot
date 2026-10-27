package com.example.rbacauth.credential;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "oauth_credentials", indexes = {
        @Index(name = "idx_credentials_owner", columnList = "owner_username")
})
public class OAuthCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "owner_username", nullable = false, length = 64)
    private String ownerUsername;

    @Column(nullable = false, length = 64)
    private String provider;

    @Column(nullable = false, length = 12000)
    private String encryptedToken;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    protected OAuthCredential() {
    }

    public OAuthCredential(String ownerUsername, String provider, String encryptedToken) {
        this.ownerUsername = ownerUsername;
        this.provider = provider;
        this.encryptedToken = encryptedToken;
    }

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public String getOwnerUsername() {
        return ownerUsername;
    }

    public String getProvider() {
        return provider;
    }

    public String getEncryptedToken() {
        return encryptedToken;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
