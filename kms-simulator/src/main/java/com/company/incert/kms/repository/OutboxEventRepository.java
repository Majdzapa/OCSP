package com.company.incert.kms.repository;

import com.company.incert.kms.entity.OutboxEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OutboxEventRepository extends JpaRepository<OutboxEvent, String> {

    List<OutboxEvent> findBySentFalseOrderByCreatedAtAsc();

    long countBySentFalse();
}
