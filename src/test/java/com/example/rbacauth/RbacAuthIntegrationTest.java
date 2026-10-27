package com.example.rbacauth;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.rbacauth.credential.OAuthCredentialRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:rbac-auth-test;DB_CLOSE_DELAY=-1",
        "app.jwt.secret=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
        "app.encryption.key=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=",
        "app.cookie-secure=false",
        "app.bootstrap-admin.username=test-admin",
        "app.bootstrap-admin.password=test-admin-password-2026"
})
@AutoConfigureMockMvc
class RbacAuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private OAuthCredentialRepository credentials;

    @Test
    void registrationAuthenticatesAndEnforcesRoles() throws Exception {
        String username = username();
        AuthSession session = register(username);

        mockMvc.perform(get("/api/users/me").header("Authorization", bearer(session.accessToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is(username)))
                .andExpect(jsonPath("$.roles[0]", is("USER")));

        mockMvc.perform(get("/api/admin").header("Authorization", bearer(session.accessToken())))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new LoginPayload(username, "incorrect-password"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("incorrect")));
    }

    @Test
    void refreshTokensRotateAndReplayRevokesTheTokenFamily() throws Exception {
        AuthSession initial = register(username());
        AuthSession rotated = refresh(initial.refreshToken());

        org.junit.jupiter.api.Assertions.assertNotEquals(initial.refreshToken(), rotated.refreshToken());

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", initial.refreshToken())))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", rotated.refreshToken())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void credentialsAreEncryptedAndOwnedByTheAuthenticatedUser() throws Exception {
        String owner = username();
        AuthSession ownerSession = register(owner);
        String secret = "oauth-secret-" + UUID.randomUUID();

        MvcResult created = mockMvc.perform(post("/api/credentials")
                        .header("Authorization", bearer(ownerSession.accessToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new CredentialPayload("GitHub", secret))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.provider", is("github")))
                .andExpect(jsonPath("$.token").doesNotExist())
                .andReturn();

        long credentialId = objectMapper.readTree(created.getResponse().getContentAsString())
                .get("id").asLong();
        var stored = credentials.findById(credentialId).orElseThrow();
        org.junit.jupiter.api.Assertions.assertNotEquals(secret, stored.getEncryptedToken());
        org.junit.jupiter.api.Assertions.assertTrue(stored.getEncryptedToken().startsWith("v1."));

        mockMvc.perform(get("/api/credentials/{id}", credentialId)
                        .header("Authorization", bearer(ownerSession.accessToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.provider", is("github")))
                .andExpect(jsonPath("$.token").doesNotExist());

        mockMvc.perform(get("/api/credentials/{id}/secret", credentialId)
                        .header("Authorization", bearer(ownerSession.accessToken())))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.token", is(secret)));

        AuthSession otherSession = register(username());
        mockMvc.perform(get("/api/credentials/{id}", credentialId)
                        .header("Authorization", bearer(otherSession.accessToken())))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/credentials/{id}/secret", credentialId)
                        .header("Authorization", bearer(otherSession.accessToken())))
                .andExpect(status().isNotFound());

        mockMvc.perform(delete("/api/credentials/{id}", credentialId)
                        .header("Authorization", bearer(ownerSession.accessToken())))
                .andExpect(status().isNoContent());
    }

    @Test
    void bootstrappedAdministratorCanReachAdminEndpoint() throws Exception {
        AuthSession admin = login("test-admin", "test-admin-password-2026");

        mockMvc.perform(get("/api/admin").header("Authorization", bearer(admin.accessToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", containsString("administrator")));
    }

    @Test
    void publicHealthAndInputValidationWork() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("UP")));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new RegisterPayload("ab", "short"))))
                .andExpect(status().isBadRequest());
    }

    private AuthSession register(String username) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new RegisterPayload(username, "long-enough-password-2026"))))
                .andExpect(status().isOk())
                .andExpect(header().string("Set-Cookie", containsString("HttpOnly")))
                .andExpect(header().string("Set-Cookie", containsString("SameSite=Strict")))
                .andReturn();
        return sessionFrom(result);
    }

    private AuthSession login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new LoginPayload(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return sessionFrom(result);
    }

    private AuthSession refresh(String token) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", token)))
                .andExpect(status().isOk())
                .andReturn();
        return sessionFrom(result);
    }

    private AuthSession sessionFrom(MvcResult result) throws Exception {
        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        String setCookie = result.getResponse().getHeader("Set-Cookie");
        String refreshToken = setCookie.substring("refresh_token=".length(), setCookie.indexOf(';'));
        return new AuthSession(response.get("accessToken").asText(), refreshToken);
    }

    private String json(Object value) throws Exception {
        return objectMapper.writeValueAsString(value);
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String username() {
        return "user-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private record AuthSession(String accessToken, String refreshToken) {
    }

    private record RegisterPayload(String username, String password) {
    }

    private record LoginPayload(String username, String password) {
    }

    private record CredentialPayload(String provider, String token) {
    }
}
