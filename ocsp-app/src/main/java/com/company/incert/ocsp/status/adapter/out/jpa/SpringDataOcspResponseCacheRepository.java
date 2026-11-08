package com.company.incert.ocsp.status.adapter.out.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SpringDataOcspResponseCacheRepository extends JpaRepository<OcspResponseCacheJpaEntity, String> {
}

