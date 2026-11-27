package lu.incert.ocsp.signing.repository;

import lu.incert.ocsp.signing.entity.OcspKeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OcspKeyRepository extends JpaRepository<OcspKeyEntity, Long> {

    Optional<OcspKeyEntity> findByKeyLabel(String keyLabel);

    boolean existsByKeyLabel(String keyLabel);

    List<OcspKeyEntity> findAllByOrderByIdDesc();

    List<OcspKeyEntity> findAllByTokenDevice_IdOrderByIdDesc(Long tokenDeviceId);
}

