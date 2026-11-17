package com.company.incert.ocsp.signing;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Supported OCSP response signature algorithms and their compatible HSM key types.
 */
public enum SigningAlgorithm {
    SHA256_WITH_RSA("SHA256withRSA", "RSA"),
    SHA384_WITH_RSA("SHA384withRSA", "RSA"),
    SHA512_WITH_RSA("SHA512withRSA", "RSA"),
    SHA256_WITH_RSA_PSS("SHA256withRSAandMGF1", "RSA"),
    SHA256_WITH_ECDSA("SHA256withECDSA", "EC"),
    SHA384_WITH_ECDSA("SHA384withECDSA", "EC"),
    SHA512_WITH_ECDSA("SHA512withECDSA", "EC");

    private final String algorithmName;
    private final String keyType;

    SigningAlgorithm(String algorithmName, String keyType) {
        this.algorithmName = algorithmName;
        this.keyType = keyType;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public String getKeyType() {
        return keyType;
    }

    public static List<String> namesForKeyType(String keyType) {
        return Arrays.stream(values())
                .filter(a -> a.keyType.equalsIgnoreCase(keyType))
                .map(SigningAlgorithm::getAlgorithmName)
                .toList();
    }

    public static Map<String, List<String>> groupedByKeyType() {
        return Arrays.stream(values())
                .collect(Collectors.groupingBy(
                        SigningAlgorithm::getKeyType,
                        Collectors.mapping(SigningAlgorithm::getAlgorithmName, Collectors.toList())
                ));
    }

    public static boolean isSupportedForKeyType(String algorithmName, String keyType) {
        return Arrays.stream(values())
                .anyMatch(a -> a.keyType.equalsIgnoreCase(keyType) && a.algorithmName.equals(algorithmName));
    }

    public static SigningAlgorithm defaultForKeyType(String keyType) {
        return "EC".equalsIgnoreCase(keyType) ? SHA256_WITH_ECDSA : SHA256_WITH_RSA;
    }
}

