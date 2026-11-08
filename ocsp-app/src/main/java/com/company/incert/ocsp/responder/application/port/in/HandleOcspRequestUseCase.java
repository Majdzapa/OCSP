package com.company.incert.ocsp.responder.application.port.in;

/** Driving port: handle a raw DER-encoded OCSP request and return a DER response. */
public interface HandleOcspRequestUseCase {
    byte[] handle(byte[] derRequest);
}

