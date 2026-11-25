# Utimaco CryptoServer / SecurityServer PKCS#11 R3 Setup

This folder provides a zero-code drop-in overlay for integrating **Utimaco CryptoServer / SecurityServer** (or the **Utimaco SecurityServer Simulator**) with `ocsp-responder` via the existing `PKCS11J` (`org.xipki:ipkcs11wrapper`) provider.

---

## 1. Place the Vendor Binary

Download the **Utimaco SecurityServer SDK** from the [Utimaco Support Portal](https://support.hsm.utimaco.com/) or request the [GP HSM Simulator](https://utimaco.com/products/hsm-simulators-and-product-trials/try-gp-hsm-simulator).

Copy the Linux x86_64 PKCS#11 R3 library here:

```bash
cp <UTIMACO_SDK>/Software/Linux/x86-64/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so ./utimaco/libcs_pkcs11_R3.so
```

> Proprietary `.so` binaries are ignored by `utimaco/.gitignore` and will never be committed to Git.

---

## 2. Configure the HSM Endpoint

Edit `utimaco/cs_pkcs11_R3.cfg` and set `Device`:

```ini
# Single HSM appliance
Device = 3001@10.10.1.50

# Or HA cluster (automatic failover)
Device = 3001@10.10.1.50;3001@10.10.1.51
```

---

## 3. Start `ocsp-responder` with the Utimaco Overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.utimaco.yml up -d ocsp-responder
```

*(On Apple Silicon / ARM64 hosts, uncomment `platform: linux/amd64` in `docker-compose.utimaco.yml` so the container matches Utimaco's x86_64 `.so`.)*

---

## 4. Register Provider, Discover Slots & Unlock (Zero Restart)

Open **http://localhost:8080/console/hsm-devices** (or use the Admin REST API):

1. **Providers → Add Provider**:
   - **Code**: `utimaco-r3`
   - **Name**: `Utimaco CryptoServer R3`
   - **Wrapper Type**: `PKCS11J`
   - **PKCS#11 Vendor Library Path**: `/opt/utimaco/lib/libcs_pkcs11_R3.so`
   - **JNI Library Wrapper Path**: *(leave blank — uses built-in `ipkcs11wrapper` loader)*
2. Click **Scan Slots** (zero-PIN `C_GetSlotList`) → **Configure Device** on your Utimaco slot (e.g. `deviceId = utimaco-ca1`, `poolSize = 4`).
3. Click **Unlock** on `utimaco-ca1` and supply the Utimaco Crypto User PIN (Pattern 2 — wiped immediately from RAM after `C_Login`).
4. Go to **Signing Certificates → Generate CSR** selecting `utimaco-ca1`, sign with your CA, and upload/activate the certificate.

