package com.company.incert.kms.adapter.out.jpa;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "outbox_event")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OutboxEventJpaEntity {

    @Id
    @Column(name = "event_id", nullable = false, length = 64)
    private String eventId;

    @Column(name = "topic", nullable = false, length = 128)
    private String topic;

    @Column(name = "kafka_key", nullable = false, length = 256)
    private String kafkaKey;

    @Column(name = "payload", columnDefinition = "TEXT NOT NULL")
    private String payload;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "sent_at")
    private Instant sentAt;

    @Column(name = "sent", nullable = false)
    private boolean sent;
}
