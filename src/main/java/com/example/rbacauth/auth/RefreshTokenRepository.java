package com.example.rbacauth.auth;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select token from RefreshToken token where token.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    @Modifying
    @Query("update RefreshToken token set token.revokedAt = :revokedAt where token.familyId = :familyId and token.revokedAt is null")
    int revokeActiveFamily(@Param("familyId") String familyId, @Param("revokedAt") Instant revokedAt);

    @Modifying
    @Query("update RefreshToken token set token.revokedAt = :revokedAt where token.tokenHash = :tokenHash and token.revokedAt is null")
    int revokeToken(@Param("tokenHash") String tokenHash, @Param("revokedAt") Instant revokedAt);
}
