package lu.incert.ocsp.signing.port;

/**
 * Interface-segregated lifecycle contract for cryptographic devices supporting Pattern 2
 * (Runtime Activation): boot in {@link DeviceActivationState#LOCKED} state with zero stored PINs,
 * unlock in memory via {@link #activate(char[])}, and wipe/logout via {@link #deactivate()}.
 */
public interface ActivatableCryptoProvider {

    DeviceActivationState activationState();

    void activate(char[] pin);

    void deactivate();
}

