package lu.incert.ocsp.signing.pkcs11.crypto;

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

    public List<KeyPairStrategy> all() {
        return List.copyOf(strategies);
    }

    public KeyPairStrategy resolve(String keyAlgorithm) {
        if (keyAlgorithm == null || keyAlgorithm.isBlank()) {
            throw new IllegalArgumentException("Key algorithm must be explicitly specified (registered: "
                    + strategies.stream().map(KeyPairStrategy::keyAlgorithmName).toList() + ")");
        }
        for (KeyPairStrategy strategy : strategies) {
            if (strategy.supports(keyAlgorithm)) {
                return strategy;
            }
        }
        throw new IllegalArgumentException("Unsupported PKCS#11 key algorithm: '" + keyAlgorithm
                + "'. Registered: " + strategies.stream().map(KeyPairStrategy::keyAlgorithmName).toList());
    }
}

