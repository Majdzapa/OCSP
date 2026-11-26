package lu.incert.ocsp.signing.pkcs11.crypto;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Open-Closed registry of {@link SignatureStrategy} implementations.
 */
public final class SignatureStrategies {

    private final CopyOnWriteArrayList<SignatureStrategy> strategies = new CopyOnWriteArrayList<>(List.of(
            new EcdsaSignatureStrategy(),
            new RsaPssSignatureStrategy(),
            new RsaPkcsSignatureStrategy()
    ));

    public void register(SignatureStrategy strategy) {
        if (strategy != null) {
            strategies.add(0, strategy);
        }
    }

    public List<SignatureStrategy> all() {
        return List.copyOf(strategies);
    }

    public SignatureStrategy resolve(String signatureAlgorithm) {
        if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
            throw new IllegalArgumentException(
                    "Signature algorithm must be explicitly specified (registered: "
                            + strategies.stream().flatMap(s -> s.supportedAlgorithms().stream()).toList() + ")");
        }
        String alg = signatureAlgorithm.trim();
        for (SignatureStrategy strategy : strategies) {
            if (strategy.supports(alg)) {
                return strategy;
            }
        }
        throw new IllegalArgumentException("Unsupported signature algorithm: '" + alg
                + "'. Registered: "
                + strategies.stream().flatMap(s -> s.supportedAlgorithms().stream()).toList());
    }
}

