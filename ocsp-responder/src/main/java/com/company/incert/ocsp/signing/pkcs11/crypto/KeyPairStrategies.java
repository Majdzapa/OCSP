package com.company.incert.ocsp.signing.pkcs11.crypto;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Open-Closed registry of {@link KeyPairStrategy} implementations.
 */
public final class KeyPairStrategies {

    private final CopyOnWriteArrayList<KeyPairStrategy> strategies = new CopyOnWriteArrayList<>(List.of(
            new EcKeyPairStrategy(),
            new RsaKeyPairStrategy()
    ));

    public void register(KeyPairStrategy strategy) {
        if (strategy != null) {
            strategies.add(0, strategy);
        }
    }

    public KeyPairStrategy resolve(String keyAlgorithm) {
        for (KeyPairStrategy strategy : strategies) {
            if (strategy.supports(keyAlgorithm)) {
                return strategy;
            }
        }
        throw new IllegalArgumentException("Unsupported PKCS#11 key algorithm: " + keyAlgorithm);
    }
}

