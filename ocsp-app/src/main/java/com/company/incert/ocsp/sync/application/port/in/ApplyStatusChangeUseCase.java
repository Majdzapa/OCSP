package com.company.incert.ocsp.sync.application.port.in;

import com.company.incert.ocsp.sync.domain.StatusChangeCommand;

public interface ApplyStatusChangeUseCase {
    void apply(StatusChangeCommand command);
}

