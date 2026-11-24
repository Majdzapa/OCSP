package lu.incert.ocsp.trust.repository;

import lu.incert.ocsp.trust.entity.TrustedCaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TrustedCaRepository extends JpaRepository<TrustedCaEntity, String> {

    List<TrustedCaEntity> findAllByOrderByCreatedAtDesc();

    List<TrustedCaEntity> findByEnabledTrue();

    boolean existsByAliasIgnoreCase(String alias);

    boolean existsByFingerprintSha256(String fingerprintSha256);
}

