#!/usr/bin/env bash
# =============================================================================
# dev-start.sh — Start the full OCSP subsystem locally for development testing.
#
# Services started (in order):
#   1. MariaDB + RabbitMQ        (Docker Compose)
#   2. Flyway migrations         (Maven)
#   3. KMS mock                  (port 8085)
#   4. ocsp-auth                 (port 9000)
#   5. ocsp-sync-service         (port 8081)
#   6. ocsp-responder            (port 8080)
#   7. ocsp-admin-api            (port 8082)
#   8. ocsp-console              (port 5173, Vite dev server)
#
# Ports in use: 8080, 8081, 8082, 8085, 9000, 3306, 5672, 15672, 5173
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOGS="$ROOT/.dev-logs"
mkdir -p "$LOGS"

# Lombok 1.18.34 fails under Java 25 — force a JDK 21 for Maven and the services.
if [[ -z "${JAVA_HOME:-}" ]] || ! "$JAVA_HOME/bin/java" -version 2>&1 | grep -q '"21'; then
    JAVA_HOME="$(/usr/libexec/java_home -v 21 2>/dev/null || echo "$HOME/Library/Java/JavaVirtualMachines/corretto-21.0.9/Contents/Home")"
fi
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

wait_for_port() {
    local name=$1 port=$2 retries=${3:-30}
    info "Waiting for $name on port $port..."
    for i in $(seq 1 $retries); do
        if nc -z localhost "$port" 2>/dev/null; then
            info "$name is up ✔"
            return 0
        fi
        sleep 2
    done
    error "$name did not start on port $port after $((retries * 2))s"
    return 1
}

# ---------------------------------------------------------------------------
# 1. MariaDB + RabbitMQ via Docker Compose
# ---------------------------------------------------------------------------
# Host ports (docker-compose maps MariaDB 3307->3306; 8080 is often taken locally)
DB_PORT="${DB_PORT:-3307}"
RESPONDER_PORT="${RESPONDER_PORT:-8090}"
export SPRING_DATASOURCE_URL="jdbc:mariadb://localhost:${DB_PORT}/ocsp"

info "Starting infrastructure (MariaDB + RabbitMQ)..."
cd "$ROOT"
docker compose up -d mariadb rabbitmq 2>&1 | tail -5
wait_for_port "MariaDB"  "$DB_PORT" 30
wait_for_port "RabbitMQ" 5672 30
info "Infrastructure ready ✔"

# Dev only: V2 creates users with 'changeme_in_production'; services default to 'changeme'.
# Port 3307 opens before MariaDB finishes init, so retry until the server accepts SQL.
DB_ALIGNED=false
for i in $(seq 1 30); do
    if docker exec ocsp-mariadb mariadb -uroot -p"${MARIADB_ROOT_PASSWORD:-rootpassword}" -e "
      ALTER USER IF EXISTS 'ocsp_reader'@'%' IDENTIFIED BY 'changeme';
      ALTER USER IF EXISTS 'ocsp_writer'@'%' IDENTIFIED BY 'changeme';
      ALTER USER IF EXISTS 'ocsp_admin'@'%'  IDENTIFIED BY 'changeme';
      FLUSH PRIVILEGES;" >/dev/null 2>&1; then
        DB_ALIGNED=true
        break
    fi
    sleep 2
done
if $DB_ALIGNED; then info "Dev DB passwords aligned ✔"; else warn "Could not align DB passwords"; fi

# ---------------------------------------------------------------------------
# 2. Run Flyway migrations (via ocsp-sync-service pom — it has Flyway dep)
# ---------------------------------------------------------------------------
# Migrations are applied automatically on first Spring Boot startup (ddl-auto=validate + Flyway).
# If you need to run them manually: 
#   cd $ROOT && mvn -pl ocsp-sync-service flyway:migrate -Dflyway.url=... 

# ---------------------------------------------------------------------------
# 3. Build all Maven modules (skip tests for speed)
# ---------------------------------------------------------------------------
info "Building OCSP Maven modules (skip tests)..."
cd "$ROOT"
mvn clean package -DskipTests -q 2>&1 | tail -20
info "Build complete ✔"

info "Building KMS mock..."
cd "$ROOT/KMS"
mvn clean package -DskipTests -q 2>&1 | tail -10
info "KMS build complete ✔"

# ---------------------------------------------------------------------------
# Helper: start a Spring Boot jar in background
# ---------------------------------------------------------------------------
start_service() {
    local name=$1
    local jar=$2
    local port=$3
    shift 3
    local extra_args=("$@")

    info "Starting $name (port $port)..."
    nohup java -jar "$jar" ${extra_args[@]+"${extra_args[@]}"} \
        > "$LOGS/${name}.log" 2>&1 &
    echo $! > "$LOGS/${name}.pid"
    wait_for_port "$name" "$port"
}

# ---------------------------------------------------------------------------
# 4. KMS mock
# ---------------------------------------------------------------------------
start_service "kms-mock" \
    "$ROOT/KMS/target/kms-mock-1.0.0-SNAPSHOT.jar" \
    8085

# ---------------------------------------------------------------------------
# 5. ocsp-auth (Spring Authorization Server)
# ---------------------------------------------------------------------------
start_service "ocsp-auth" \
    "$ROOT/ocsp-auth/target/ocsp-auth-1.0.0-SNAPSHOT.jar" \
    9000

# ---------------------------------------------------------------------------
# 6. ocsp-sync-service
# ---------------------------------------------------------------------------
start_service "ocsp-sync" \
    "$ROOT/ocsp-sync-service/target/ocsp-sync-service-1.0.0-SNAPSHOT.jar" \
    8081 \
    --kms.base-url=http://localhost:8085 \
    --kms.mtls.enabled=false

# ---------------------------------------------------------------------------
# 7. ocsp-responder
# ---------------------------------------------------------------------------
start_service "ocsp-responder" \
    "$ROOT/ocsp-responder/target/ocsp-responder-1.0.0-SNAPSHOT.jar" \
    "$RESPONDER_PORT" \
    --server.port="$RESPONDER_PORT" \
    --kms.base-url=http://localhost:8085 \
    --kms.mtls.enabled=false

# ---------------------------------------------------------------------------
# 8. ocsp-admin-api
# ---------------------------------------------------------------------------
start_service "ocsp-admin-api" \
    "$ROOT/ocsp-admin-api/target/ocsp-admin-api-1.0.0-SNAPSHOT.jar" \
    8082 \
    --spring.datasource.url="jdbc:mariadb://127.0.0.1:${DB_PORT}/ocsp" \
    --spring.datasource.username="ocsp_admin" \
    --spring.datasource.password="changeme" \
    --OIDC_ISSUER_URI=http://localhost:9000 \
    --CORS_ALLOWED_ORIGINS=http://localhost:5173 \
    --kms.base-url=http://localhost:8085

# ---------------------------------------------------------------------------
# 9. ocsp-console (Vite dev server)
# ---------------------------------------------------------------------------
info "Starting ocsp-console (Vite, port 5173)..."
cd "$ROOT/ocsp-console"
nohup npm run dev -- --port 5173 > "$LOGS/ocsp-console.log" 2>&1 &
echo $! > "$LOGS/ocsp-console.pid"
wait_for_port "ocsp-console" 5173

# ---------------------------------------------------------------------------
# Done — print access info
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo -e "${GREEN}✅ All OCSP services are running!${NC}"
echo "============================================================"
echo ""
echo "  🌐 Admin Console  : http://localhost:5173"
echo "  🔐 Auth Server    : http://localhost:9000"
echo "  🔧 Admin API      : http://localhost:8082/api/v1/admin"
echo "  📡 OCSP Responder : http://localhost:${RESPONDER_PORT}/ocsp"
echo "  🔑 KMS Mock       : http://localhost:8085"
echo "  🐇 RabbitMQ UI    : http://localhost:15672  (guest/guest)"
echo ""
echo "  📋 Logs: $LOGS/"
echo ""
echo "  Get a JWT token:"
echo "    curl -s -X POST http://localhost:9000/oauth2/token \\"
echo "      -u 'ocsp-console:secret' \\"
echo "      -d 'grant_type=client_credentials&scope=ocsp.admin' | jq -r .access_token"
echo ""
echo "  Stop all: $ROOT/scripts/dev-stop.sh"
