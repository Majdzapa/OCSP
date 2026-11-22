package com.company.incert.ocsp.signing.usecase;

import com.company.incert.ocsp.signing.entity.SigningCertificate;
import com.company.incert.ocsp.signing.repository.SigningCertificateRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Loads a signing certificate by id or fails with a uniform {@link IllegalArgumentException}.
 * Shared by activation, deactivation, deletion and renewal flows, which all start with this lookup.
 */
@Component
@RequiredArgsConstructor
public class FindSigningCertificateUseCase {

    private final SigningCertificateRepository repository;

    public SigningCertificate execute(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Signing certificate not found with id: " + id));
    }
}

