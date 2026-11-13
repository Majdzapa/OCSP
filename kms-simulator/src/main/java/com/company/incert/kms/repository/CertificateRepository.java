package com.company.incert.kms.repository;

import com.company.incert.kms.entity.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    Optional<Certificate> findBySerialNumberHex(String serialNumberHex);

    List<Certificate> findAllByOrderBySerialNumberHexAsc();
}

