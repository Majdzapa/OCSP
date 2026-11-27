package lu.incert.ocsp.signing.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * Ordered binding between an {@link OcspSignerEntity} and a PKCS#11 HSM Token ({@link CryptoDeviceEntity}).
 * {@code priorityOrder = 0} denotes the {@code PRIMARY} token; {@code 1..N} denote {@code FAILOVER} tokens.
 */
@Entity
@Table(name = "ocsp_signer_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OcspSignerTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "signer_id", nullable = false)
    private OcspSignerEntity signer;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "token_device_id", nullable = false)
    private CryptoDeviceEntity tokenDevice;

    @Column(name = "priority_order", nullable = false)
    @Builder.Default
    private int priorityOrder = 0;

    @Column(nullable = false, length = 32)
    @Builder.Default
    private String role = "PRIMARY";
}

