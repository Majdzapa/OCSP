#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_OUT_BASE="${1:-${SCRIPT_DIR}/../target/classes/native}"

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

case "${UNAME_S}" in
    Darwin)
        OS_NAME="osx"
        JNI_OS_INC="darwin"
        LIB_EXT="dylib"
        LINK_FLAGS=""
        ;;
    Linux)
        OS_NAME="linux"
        JNI_OS_INC="linux"
        LIB_EXT="so"
        LINK_FLAGS="-ldl"
        ;;
    *)
        echo "Unsupported OS for pkcs11j native build: ${UNAME_S}" >&2
        exit 1
        ;;
esac

case "${UNAME_M}" in
    arm64|aarch64)
        ARCH_NAME="aarch64"
        ;;
    x86_64|amd64)
        ARCH_NAME="x86_64"
        ;;
    *)
        ARCH_NAME="${UNAME_M}"
        ;;
esac

# Resolve JAVA_HOME containing jni.h
resolve_java_home() {
    if [ -n "${JAVA_HOME:-}" ] && [ -f "${JAVA_HOME}/include/jni.h" ]; then
        echo "${JAVA_HOME}"
        return 0
    fi
    local java_home_prop
    java_home_prop="$(java -XshowSettings:properties -version 2>&1 | awk -F'= ' '/java.home/{print $2; exit}' | tr -d '[:space:]')" || true
    if [ -n "${java_home_prop}" ] && [ -f "${java_home_prop}/include/jni.h" ]; then
        echo "${java_home_prop}"
        return 0
    fi
    for candidate in \
        "/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home" \
        "/opt/homebrew/Cellar/openjdk/25.0.1/libexec/openjdk.jdk/Contents/Home" \
        "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home" \
        "/usr/lib/jvm/default-java"; do
        if [ -f "${candidate}/include/jni.h" ]; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

RESOLVED_JAVA_HOME="$(resolve_java_home)" || {
    echo "Could not locate JAVA_HOME with include/jni.h" >&2
    exit 1
}

CC_BIN="${CC:-cc}"
OUT_DIR="${NATIVE_OUT_BASE}/${OS_NAME}-${ARCH_NAME}"
mkdir -p "${OUT_DIR}"
OUT_LIB="${OUT_DIR}/libpkcs11j.${LIB_EXT}"

echo "[pkcs11j] Compiling native JNI library -> ${OUT_LIB} (JAVA_HOME=${RESOLVED_JAVA_HOME})"
"${CC_BIN}" -O2 -Wall -Wextra -shared -fPIC \
    -I"${SCRIPT_DIR}/include" \
    -I"${RESOLVED_JAVA_HOME}/include" \
    -I"${RESOLVED_JAVA_HOME}/include/${JNI_OS_INC}" \
    "${SCRIPT_DIR}/src/pkcs11j_jni.c" \
    ${LINK_FLAGS} \
    -o "${OUT_LIB}"

