package com.company.incert.kms.adapter.out.jpa;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SpringDataOutboxRepository extends JpaRepository<OutboxEventJpaEntity, String> {
    List<OutboxEventJpaEntity> findBySentFalseOrderByCreatedAtAsc();
}
