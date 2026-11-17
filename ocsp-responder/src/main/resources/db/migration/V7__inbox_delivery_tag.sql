-- V7__inbox_delivery_tag.sql
-- Track RabbitMQ AMQP delivery metadata (delivery_tag, consumer_queue, redelivered) in inbox_event
-- so failed or redelivered broker messages can be traced directly to RabbitMQ deliveries.

ALTER TABLE inbox_event
    ADD COLUMN IF NOT EXISTS delivery_tag BIGINT NULL COMMENT 'RabbitMQ AMQP channel delivery tag',
    ADD COLUMN IF NOT EXISTS consumer_queue VARCHAR(128) NULL COMMENT 'RabbitMQ queue name',
    ADD COLUMN IF NOT EXISTS redelivered BOOLEAN NULL COMMENT 'Whether RabbitMQ redelivered the message';

