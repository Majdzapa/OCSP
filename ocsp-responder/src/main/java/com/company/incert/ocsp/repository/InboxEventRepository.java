package com.company.incert.ocsp.repository;

import com.company.incert.ocsp.entity.InboxEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface InboxEventRepository extends JpaRepository<InboxEvent, String> {

    Optional<InboxEvent> findByEventId(String eventId);

    List<InboxEvent> findByCertificateSerialOrderByReceivedAtDesc(String certificateSerial);

    Page<InboxEvent> findAllByOrderByReceivedAtDesc(Pageable pageable);

    long countByProcessingStatus(String processingStatus);
}

