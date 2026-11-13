package com.company.incert.ocsp.repository;

import com.company.incert.ocsp.entity.SigningCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SigningCertificateRepository extends JpaRepository<SigningCertificate, Long> {

    Optional<SigningCertificate> findByActiveTrue();

    Optional<SigningCertificate> findByAlias(String alias);

    boolean existsByAlias(String alias);

    @Modifying
    @Query("UPDATE SigningCertificate c SET c.active = false")
    void deactivateAll();
}

