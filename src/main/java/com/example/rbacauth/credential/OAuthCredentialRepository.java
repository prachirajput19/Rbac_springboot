package com.example.rbacauth.credential;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthCredentialRepository extends JpaRepository<OAuthCredential, Long> {

    List<OAuthCredential> findAllByOwnerUsernameOrderByCreatedAtDesc(String ownerUsername);

    Optional<OAuthCredential> findByIdAndOwnerUsername(Long id, String ownerUsername);
}
