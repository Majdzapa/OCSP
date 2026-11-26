package lu.incert.ocsp.signing.repository;

import lu.incert.ocsp.signing.entity.OcspSignerEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OcspSignerRepository extends JpaRepository<OcspSignerEntity, Long> {

    List<OcspSignerEntity> findAllByOrderByIdAsc();

    List<OcspSignerEntity> findAllByActiveTrueOrderByActivatedAtDesc();

    Optional<OcspSignerEntity> findByCode(String code);

    Optional<OcspSignerEntity> findBySigningCertificateId(Long signingCertificateId);

    boolean existsByCode(String code);
}

