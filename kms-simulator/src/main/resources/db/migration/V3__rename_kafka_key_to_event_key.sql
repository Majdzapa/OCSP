-- V3__rename_kafka_key_to_event_key.sql
-- Transition column kafka_key to event_key for RabbitMQ messaging

ALTER TABLE outbox_event
    CHANGE COLUMN kafka_key event_key VARCHAR(256) NOT NULL COMMENT 'Event routing/partition key';

ALTER TABLE outbox_event
    COMMENT='Transactional outbox for RabbitMQ events';

