-- V4__remove_cache.sql
-- Remove caching tables and unused Kafka offset tracking in monolith architecture.

DROP TABLE IF EXISTS ocsp_response_cache;
DROP TABLE IF EXISTS kafka_consumer_offset;
DROP TABLE IF EXISTS event_publication;

