package lu.incert.ocsp.signing.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 *Ordered binding between an {@link OcspSignerEntity} and an HSM Vslot ({@link CryptoDeviceEntity}).
 * {@code priorityOrder = 0} denotes the {@code PRIMARY} Vslot; {@code 1..N} denote {@code FAILOVER} Vslots.
 */
@Entity
@Table(name = "ocsp_signer_vslots")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OcspSignerVslotEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "signer_id", nullable = false)
    private OcspSignerEntity signer;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "device_id", nullable = false)
    private CryptoDeviceEntity device;

    @Column(name = "priority_order", nullable = false)
    @Builder.Default
    private int priorityOrder = 0;

    @Column(nullable = false, length = 32)
    @Builder.Default
    private String role = "PRIMARY";
}

