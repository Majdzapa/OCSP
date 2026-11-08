package com.company.incert.ocsp.status.application.port.out;

import java.util.List;
import java.util.Map;

public interface StatusStatsPort {
    long countTotal();
    long countRevoked();
    long countGood();
    List<Map<String, String>> getRevokedPage(int page, int size);
    java.util.Optional<Map<String, String>> findBySerial(String serialHex);
}
