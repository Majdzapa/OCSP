package com.company.incert.ocsp.signing.repository;

import com.company.incert.ocsp.signing.entity.CryptoProviderEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CryptoProviderRepository extends JpaRepository<CryptoProviderEntity, Long> {

    List<CryptoProviderEntity> findAllByOrderByIdAsc();

    Optional<CryptoProviderEntity> findByCode(String code);

    boolean existsByCode(String code);
}

