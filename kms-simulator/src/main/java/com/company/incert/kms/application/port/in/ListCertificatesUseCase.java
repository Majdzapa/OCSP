package com.company.incert.kms.application.port.in;

import com.company.incert.kms.domain.Certificate;

import java.util.List;

public interface ListCertificatesUseCase {
    List<Certificate> listAll();
}
