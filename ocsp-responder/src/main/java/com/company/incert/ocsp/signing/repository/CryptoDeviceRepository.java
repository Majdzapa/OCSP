package com.company.incert.ocsp.signing.repository;

import com.company.incert.ocsp.signing.entity.CryptoDeviceEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CryptoDeviceRepository extends JpaRepository<CryptoDeviceEntity, Long> {

    List<CryptoDeviceEntity> findAllByOrderByIdAsc();

    List<CryptoDeviceEntity> findAllByEnabledTrueOrderByIdAsc();

    List<CryptoDeviceEntity> findAllByProviderId(Long providerId);

    Optional<CryptoDeviceEntity> findByDeviceId(String deviceId);

    boolean existsByDeviceId(String deviceId);

    boolean existsByProviderId(Long providerId);

    long countByProviderId(Long providerId);
}

