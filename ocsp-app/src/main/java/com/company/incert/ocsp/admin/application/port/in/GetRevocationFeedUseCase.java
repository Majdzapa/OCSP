package com.company.incert.ocsp.admin.application.port.in;

import java.util.List;
import java.util.Map;

public interface GetRevocationFeedUseCase {
    List<Map<String, String>> getRevoked(int page, int size);
}
