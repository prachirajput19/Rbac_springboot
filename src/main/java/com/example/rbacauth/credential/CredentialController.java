package com.example.rbacauth.credential;

import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/api/credentials")
public class CredentialController {

    private final CredentialService credentialService;

    public CredentialController(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @PostMapping
    public ResponseEntity<CredentialService.CredentialMetadata> store(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody CredentialRequests.Create request,
            UriComponentsBuilder uriBuilder) {
        CredentialService.CredentialMetadata metadata = credentialService.store(jwt.getSubject(), request);
        return ResponseEntity.created(uriBuilder.path("/api/credentials/{id}")
                        .buildAndExpand(metadata.id()).toUri())
                .body(metadata);
    }

    @GetMapping
    public List<CredentialService.CredentialMetadata> list(@AuthenticationPrincipal Jwt jwt) {
        return credentialService.list(jwt.getSubject());
    }

    @GetMapping("/{id}")
    public CredentialService.CredentialMetadata get(
            @AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        return credentialService.getMetadata(jwt.getSubject(), id);
    }

    @GetMapping("/{id}/secret")
    public ResponseEntity<CredentialService.CredentialSecret> reveal(
            @AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(credentialService.reveal(jwt.getSubject(), id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        credentialService.delete(jwt.getSubject(), id);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
