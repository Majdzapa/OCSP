# Running `ocsp-responder` & `ocsp-client` Locally (macOS, Windows & Linux)

This guide explains how to run **`ocsp-responder`** and **`ocsp-client`** directly on your host machine (via Maven or your IDE) using the `local` or `dev` Spring profiles (`application-local.yml` / `application-dev.yml`), while running the backing infrastructure (`mariadb`, `rabbitmq`, `keycloak`) in Docker.

---

## 1. Prerequisites

- **Java 25** (Temurin / OpenJDK 25)
- **Maven 3.9+**
- **Docker Desktop** (for MariaDB, RabbitMQ, and Keycloak)
- **SoftHSM2** for your host OS (see OS-specific instructions below)

---

## 2. Configuration Profiles Overview

All configuration in v5.0 is externalized into YAML files and bound via typed `@ConfigurationProperties` classes in `com.company.incert.ocsp.config` (and `com.company.incert.ocsp.client.config`) with **zero hardcoded defaults in Java code**:

| Profile | Configuration Files | Description |
| :--- | :--- | :--- |
| **`dev`** *(Default)* | `ocsp-responder/src/main/resources/application-dev.yml`<br>`ocsp-client/src/main/resources/application-dev.yml` | Default profile (`spring.profiles.active: ${SPRING_PROFILES_ACTIVE:dev}`) used in Docker Compose and standard development. |
| **`local`** | `ocsp-responder/src/main/resources/application-local.yml` | Host-native profile for running `ocsp-responder` directly on macOS/Linux/Windows against Dockerized MariaDB (`:3307`), RabbitMQ (`:5671`), and Keycloak (`:8081`). |
| **`prod`** | `ocsp-responder/src/main/resources/application.yml`<br>`ocsp-client/src/main/resources/application.yml` | Environment-variable-driven production profile. |

---

## 3. Start Backing Services in Docker

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
- **Keycloak**: `http://localhost:8081` (Realm `incert`, Client `ocsp-console`, Redirect URI `http://localhost:3002/*`)

---

## 4. OS-Specific SoftHSM2 Setup

> [!IMPORTANT]
> **Zero Pre-Seeded Keys Architecture (v5.0):**
> You only initialize an **empty** SoftHSM2 token (`ocsp-signing`). No keypair or self-signed certificate is pre-created on startup. Until you generate an HSM keypair & PKCS#10 CSR, sign it in KMS (`OCSP_SIGNING`), and activate it, the responder safely answers OCSP queries with RFC 6960 `tryLater (3)`.

### Option A: macOS (Apple Silicon / Intel)

1. **Install SoftHSM2** via Homebrew:
   ```bash
   brew install softhsm
   ```
2. **Initialize the empty `ocsp-signing` token**:
   ```bash
   mkdir -p /opt/homebrew/var/lib/softhsm/tokens
   softhsm2-util --init-token --free --label ocsp-signing --so-pin 12345678 --pin 1234
   ```
3. **`application-local.yml` (Default for macOS)**:
   The repository includes the macOS Apple Silicon library at `ocsp-responder/src/main/resources/hsm/libsofthsm2.so`, configured in [application-local.yml](ocsp-responder/src/main/resources/application-local.yml):
   ```yaml
   hsm:
     enabled: true
     pkcs11-library: classpath:hsm/libsofthsm2.so
     token-label: ocsp-signing
     slot-index: 0
     pin: "1234"
     key-label: ocsp-signing-key
     config-path: ""
   ```

---

### Option B: Windows 10 / 11 (x64)

1. **Install SoftHSM2 for Windows** (e.g. `C:\SoftHSM2\lib\softhsm2-x64.dll`).
2. **Initialize the empty `ocsp-signing` token** (PowerShell):
   ```powershell
   & "C:\SoftHSM2\bin\softhsm2-util.exe" --init-token --free --label ocsp-signing --so-pin 12345678 --pin 1234
   ```
3. **Run with the Windows DLL path**:
   ```powershell
   mvn -f ocsp-responder\pom.xml spring-boot:run "-Dspring-boot.run.profiles=local" "-Dspring-boot.run.arguments=--hsm.pkcs11-library=C:/SoftHSM2/lib/softhsm2-x64.dll"
   ```

---

### Option C: Linux (Ubuntu / Debian)

1. **Install SoftHSM2**:
   ```bash
   sudo apt-get update && sudo apt-get install -y softhsm2
   ```
2. **Initialize the empty `ocsp-signing` token**:
   ```bash
   softhsm2-util --init-token --free --label ocsp-signing --so-pin 12345678 --pin 1234
   ```
3. **Run with the Linux PKCS#11 library path**:
   ```bash
   HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so \
   mvn -f ocsp-responder/pom.xml spring-boot:run -Dspring-boot.run.profiles=local
   ```

---

## 5. Provisioning Your First HSM Signing Certificate

1. Check health:
   ```bash
   curl -s http://localhost:8080/actuator/health
   ```
   Expected: `{"groups":["liveness","readiness"],"status":"UP"}`.
2. Open the **OCSP Admin Console** at `http://localhost:3002/signing-certificates` (or call `POST /api/v1/admin/signing-certificates/csr`):
   - Generate a new SoftHSM2 keypair (`RSA 3072` or `EC P-256`) and download/copy the PKCS#10 CSR PEM.
   - Open **KMS Simulator Console** (`http://localhost:3001/certificates`), paste the CSR, select your issuing CA and profile **`OCSP_SIGNING`**, and issue the certificate.
   - Import and activate the signed certificate PEM in `http://localhost:3002/signing-certificates`.

---

## 6. Running the Plain JavaScript (`.js`) Admin Console Locally

`ocsp-console` uses plain JavaScript (`.js` with `jsconfig.json`) and Vite:

```bash
cd ocsp-console
yarn install
yarn dev
```
