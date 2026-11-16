# Running `ocsp-responder` Locally (macOS, Windows & Linux)

This guide explains how to run **`ocsp-responder`** directly on your host machine (via Maven or your IDE) using the `local` Spring profile (`application-local.yml`), while running the backing infrastructure (`mariadb`, `rabbitmq`, `keycloak`) in Docker.

---

## 1. Prerequisites

- **Java 25** (Temurin / OpenJDK 25)
- **Maven 3.9+**
- **Docker Desktop** (for MariaDB, RabbitMQ, and Keycloak)
- **SoftHSM2** for your host OS (see OS-specific instructions below)

---

## 2. Start Backing Services in Docker

From the root of the `OCSP` repository, start MariaDB, RabbitMQ, and Keycloak:

```bash
docker compose up -d mariadb rabbitmq keycloak
```

> [!NOTE]
> If the containerized `ocsp-responder` is already running on port `8080`, stop it first so your local process can bind to `8080`:
> ```bash
> docker compose stop ocsp-responder
> ```

Exposed local endpoints used by `application-local.yml`:
- **MariaDB**: `jdbc:mariadb://localhost:3307/ocsp` (`ocsp_app` / `changeme`, Flyway `root` / `rootpassword`)
- **RabbitMQ (mTLS)**: `localhost:5671` (`ocsp_amqp` / `changeme`, `verify-hostname=false`)
- **Keycloak**: `http://localhost:8081`

---

## 3. OS-Specific SoftHSM2 Setup

> [!IMPORTANT]
> You do **not** need to pre-create `ocsp-signing-key` in SoftHSM2. Once the token `ocsp-signing` exists, `Pkcs11OcspSigner` automatically generates an RSA 3072 keypair inside the HSM on first startup.

### Option A: macOS (Apple Silicon / Intel)

1. **Install SoftHSM2** via Homebrew:
   ```bash
   brew install softhsm
   ```
2. **Initialize the `ocsp-signing` token**:
   ```bash
   mkdir -p /opt/homebrew/var/lib/softhsm/tokens
   softhsm2-util --init-token --free --label ocsp-signing --so-pin 12345678 --pin 1234
   ```
3. **`application-local.yml` (Default for macOS)**:
   The repository already includes the macOS Apple Silicon library at `ocsp-responder/src/main/resources/hsm/libsofthsm2.so`, configured in [application-local.yml](ocsp-responder/src/main/resources/application-local.yml):
   ```yaml
   hsm:
     enabled: true
     pkcs11-library: classpath:hsm/libsofthsm2.so
     token-label: ocsp-signing
     slot-index: 0
     pin: "1234"
     key-label: ocsp-signing-key
   ```
   *(On Intel Macs, set `HSM_PKCS11_LIBRARY=/usr/local/lib/softhsm/libsofthsm2.so` or update `hsm.pkcs11-library`.)*

---

### Option B: Windows 10 / 11 (x64)

1. **Install SoftHSM2 for Windows**:
   - Download and install the Windows SoftHSM2 build (for example from [Disig SoftHSM2-for-Windows](https://github.com/disig/SoftHSM2-for-Windows/releases) or Chocolatey/MSYS2).
   - Default installation path is typically:
     - `C:\SoftHSM2\lib\softhsm2-x64.dll`
     - `C:\SoftHSM2\etc\softhsm2.conf`
     - `C:\SoftHSM2\bin\softhsm2-util.exe`

2. **Verify `softhsm2.conf` and Token Directory** (PowerShell):
   ```powershell
   New-Item -ItemType Directory -Force -Path "C:\SoftHSM2\var\lib\softhsm\tokens"
   $env:SOFTHSM2_CONF = "C:\SoftHSM2\etc\softhsm2.conf"
   ```
   Ensure `C:\SoftHSM2\etc\softhsm2.conf` contains:
   ```ini
   directories.tokendir = C:\SoftHSM2\var\lib\softhsm\tokens
   objectstore.backend = file
   log.level = INFO
   ```

3. **Initialize the `ocsp-signing` token** (PowerShell):
   ```powershell
   & "C:\SoftHSM2\bin\softhsm2-util.exe" --init-token --free --label ocsp-signing --so-pin 12345678 --pin 1234
   ```

4. **Point `hsm.pkcs11-library` to the Windows DLL**:
   Either override via environment variable in PowerShell / IDE Run Configuration (recommended so you don't modify tracked files):
   ```powershell
   $env:HSM_PKCS11_LIBRARY = "C:/SoftHSM2/lib/softhsm2-x64.dll"
   $env:SOFTHSM2_CONF = "C:\SoftHSM2\etc\softhsm2.conf"
   ```
   Or place `softhsm2-x64.dll` in `ocsp-responder/src/main/resources/hsm/` and update `hsm.pkcs11-library` in `application-local.yml` (or pass `--hsm.pkcs11-library=C:/SoftHSM2/lib/softhsm2-x64.dll`):
   ```yaml
   hsm:
     enabled: true
     pkcs11-library: C:/SoftHSM2/lib/softhsm2-x64.dll
     token-label: ocsp-signing
     slot-index: 0
     pin: "1234"
     key-label: ocsp-signing-key
   ```
   *(Use forward slashes `/` or escaped backslashes `\\` in YAML / SunPKCS11 paths on Windows.)*

---

### Option C: Linux (Ubuntu / Debian)

1. **Install SoftHSM2**:
   ```bash
   sudo apt-get update && sudo apt-get install -y softhsm2
   ```
2. **Initialize the `ocsp-signing` token**:
   ```bash
   softhsm2-util --init-token --free --label ocsp-signing --so-pin 12345678 --pin 1234
   ```
3. **Run with the Linux PKCS#11 library path**:
   ```bash
   HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so \
   mvn -f ocsp-responder/pom.xml spring-boot:run -Dspring-boot.run.profiles=local
   ```

---

## 4. Running `ocsp-responder` Locally

### Via Maven CLI
- **macOS / Linux**:
  ```bash
  mvn -f ocsp-responder/pom.xml spring-boot:run -Dspring-boot.run.profiles=local
  ```
- **Windows (PowerShell)**:
  ```powershell
  mvn -f ocsp-responder\pom.xml spring-boot:run "-Dspring-boot.run.profiles=local" "-Dspring-boot.run.arguments=--hsm.pkcs11-library=C:/SoftHSM2/lib/softhsm2-x64.dll"
  ```

### Via IDE (IntelliJ IDEA / VS Code)
1. Main class: `com.company.incert.ocsp.OcspResponderApplication`
2. Active profile: `local`
3. Environment variables (Windows only):
   - `SOFTHSM2_CONF=C:\SoftHSM2\etc\softhsm2.conf`
   - `HSM_PKCS11_LIBRARY=C:/SoftHSM2/lib/softhsm2-x64.dll`

---

## 5. Verify Local Startup

1. Check health:
   ```bash
   curl -s http://localhost:8080/actuator/health
   ```
   Expected: `{"groups":["liveness","readiness"],"status":"UP"}`.

2. **First-time CSR & CA Certificate Import**:
   On first boot against an empty HSM token, `Pkcs11OcspSigner` generates a new RSA 3072 keypair (`ocsp-signing-key`) with a temporary self-signed certificate. To sign responses trusted by your CA:
   - Open `http://localhost:3000/signing-cert` (or call `POST /api/v1/admin/signing-certificates/csr` with `reuseExistingKey=true`),
   - Download the `.csr` file, have your CA sign it with `OCSPSigning` EKU,
   - Import the signed certificate in the UI.

---

## 6. Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `Port 8080 was already in use` | Docker `ocsp-responder` is still running | Run `docker compose stop ocsp-responder` |
| `CKR_TOKEN_NOT_PRESENT` / slot 0 uninitialized | SoftHSM2 token `ocsp-signing` was not initialized | Run `softhsm2-util --init-token --free --label ocsp-signing --so-pin 12345678 --pin 1234` |
| `Response Verify Failure` (`rsa_ossl_public_decrypt`) | `signing_certificates` in MariaDB still holds the Docker HSM container's certificate while running against a different local SoftHSM2 keypair | Generate a CSR (`reuseExistingKey=true`) and import + activate the new certificate in the UI, or reset DB (`docker compose down -v mariadb`) |
| `dlopen` / `UnsatisfiedLinkError` on Windows | `libsofthsm2.so` is a macOS binary | Override `hsm.pkcs11-library` to `C:/SoftHSM2/lib/softhsm2-x64.dll` |

