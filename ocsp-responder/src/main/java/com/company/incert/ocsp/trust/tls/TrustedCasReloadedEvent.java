package com.company.incert.ocsp.trust.tls;

/**
 * Published whenever the in-memory Trusted CA list changes so Tomcat's native TLS
 * {@code SSLHostConfig} reloads immediately without restarting the JVM.
 */
public record TrustedCasReloadedEvent(int activeCount) {}

