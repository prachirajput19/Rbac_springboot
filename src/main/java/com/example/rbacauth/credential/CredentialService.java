package com.example.rbacauth.credential;

import com.example.rbacauth.api.ApiException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CredentialService {

    private final OAuthCredentialRepository credentials;
    private final CredentialEncryptionService encryption;

    public CredentialService(OAuthCredentialRepository credentials, CredentialEncryptionService encryption) {
        this.credentials = credentials;
        this.encryption = encryption;
    }

    @Transactional
    public CredentialMetadata store(String owner, CredentialRequests.Create request) {
        if (request.token().getBytes(StandardCharsets.UTF_8).length > 8192) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "OAuth token must not exceed 8192 UTF-8 bytes.");
        }
        OAuthCredential credential = credentials.save(new OAuthCredential(owner,
                request.provider().toLowerCase(java.util.Locale.ROOT), encryption.encrypt(request.token())));
        return metadata(credential);
    }

    @Transactional(readOnly = true)
    public List<CredentialMetadata> list(String owner) {
        return credentials.findAllByOwnerUsernameOrderByCreatedAtDesc(owner).stream()
                .map(CredentialService::metadata)
                .toList();
    }

    @Transactional(readOnly = true)
    public CredentialMetadata getMetadata(String owner, long id) {
        return metadata(findOwned(owner, id));
    }

    @Transactional(readOnly = true)
    public CredentialSecret reveal(String owner, long id) {
        OAuthCredential credential = findOwned(owner, id);
        return new CredentialSecret(credential.getId(), credential.getProvider(),
                encryption.decrypt(credential.getEncryptedToken()));
    }

    @Transactional
    public void delete(String owner, long id) {
        credentials.delete(findOwned(owner, id));
    }

    private OAuthCredential findOwned(String owner, long id) {
        return credentials.findByIdAndOwnerUsername(id, owner)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Credential was not found."));
    }

    private static CredentialMetadata metadata(OAuthCredential credential) {
        return new CredentialMetadata(credential.getId(), credential.getProvider(), credential.getCreatedAt());
    }

    public record CredentialMetadata(long id, String provider, java.time.Instant createdAt) {
    }

    public record CredentialSecret(long id, String provider, String token) {
    }
}
