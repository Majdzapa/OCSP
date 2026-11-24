package lu.incert.ocsp.rabbitmq.repository;

import lu.incert.ocsp.rabbitmq.entity.InboxEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface InboxEventRepository extends JpaRepository<InboxEvent, String> {

    Optional<InboxEvent> findByEventId(String eventId);

    List<InboxEvent> findByCertificateSerialOrderByReceivedAtDesc(String certificateSerial);

    List<InboxEvent> findByCertificateSerialContainingIgnoreCaseOrderByReceivedAtDesc(String certificateSerial);

    Page<InboxEvent> findAllByOrderByReceivedAtDesc(Pageable pageable);

    long countByProcessingStatus(String processingStatus);

    @Query("SELECT i.eventId FROM InboxEvent i WHERE i.processingStatus = :status")
    List<String> findEventIdsByProcessingStatus(@Param("status") String status, Pageable pageable);

    @Query("SELECT i.eventId FROM InboxEvent i WHERE i.eventId IN :eventIds")
    List<String> findExistingEventIds(@Param("eventIds") Collection<String> eventIds);
}

