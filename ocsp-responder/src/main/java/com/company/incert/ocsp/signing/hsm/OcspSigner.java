package com.company.incert.ocsp.signing.hsm;

/**
 * Composite signing port combining runtime OCSP response signing ({@link OcspResponseSigner})
 * and device/certificate provisioning ({@link SigningDeviceManager}).
 */
public interface OcspSigner extends OcspResponseSigner, SigningDeviceManager {}
