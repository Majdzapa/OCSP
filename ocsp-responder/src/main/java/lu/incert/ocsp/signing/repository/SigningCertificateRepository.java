package lu.incert.ocsp.signing.repository;

import lu.incert.ocsp.signing.entity.SigningCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SigningCertificateRepository extends JpaRepository<SigningCertificate, Long> {

    List<SigningCertificate> findAllByActiveTrueOrderByActivatedAtDesc();

    long countByActiveTrue();

    Optional<SigningCertificate> findByAlias(String alias);

    boolean existsByAlias(String alias);

    boolean existsByProviderIdAndActiveTrue(String providerId);
}
