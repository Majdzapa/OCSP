package com.company.incert.ocsp.repository;

import com.company.incert.ocsp.entity.SigningCertificate;
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
}
