package lu.incert.ocsp.auth.repository;

import lu.incert.ocsp.auth.entity.UserCertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserCertificateRepository extends JpaRepository<UserCertificateEntity, String> {

    List<UserCertificateEntity> findByUserIdOrderByCreatedAtDesc(String userId);

    boolean existsByFingerprintSha256(String fingerprintSha256);

    @Query("""
           SELECT uc FROM UserCertificateEntity uc
           JOIN FETCH uc.user u
           LEFT JOIN FETCH u.roles
           WHERE uc.fingerprintSha256 = :fingerprint
             AND uc.revoked = false
             AND u.deletedAt IS NULL
             AND u.enabled = true
           """)
    Optional<UserCertificateEntity> findActiveWithUserByFingerprint(@Param("fingerprint") String fingerprint);
}

