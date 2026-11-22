package com.company.incert.ocsp.auth.repository;

import com.company.incert.ocsp.auth.entity.IdentityOutboxEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IdentityOutboxRepository extends JpaRepository<IdentityOutboxEntity, String> {
    List<IdentityOutboxEntity> findTop50ByProcessedFalseOrderByCreatedAtAsc();
}

