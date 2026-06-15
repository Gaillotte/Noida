#!/usr/bin/env bash
# Quick initialization script for the KMS
set -euo pipefail

echo "==> KMS Initialization Script"
echo ""

# Detect SoftHSM2 library path
SOFTHSM_LIB=""
for path in \
  /usr/lib/softhsm/libsofthsm2.so \
  /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  /usr/local/lib/softhsm/libsofthsm2.so \
  /opt/homebrew/lib/softhsm/libsofthsm2.so; do
  if [ -f "$path" ]; then
    SOFTHSM_LIB="$path"
    break
  fi
done

if [ -z "$SOFTHSM_LIB" ]; then
  echo "ERROR: SoftHSM2 library not found. Install with:"
  echo "  apt-get install softhsm2   # Debian/Ubuntu"
  echo "  brew install softhsm       # macOS"
  exit 1
fi

echo "  SoftHSM2 library: $SOFTHSM_LIB"

# Create token directory
mkdir -p /var/lib/softhsm/tokens 2>/dev/null || \
  mkdir -p "${HOME}/.softhsm2/tokens" 2>/dev/null || true

# Initialize token
HSM_PIN="${HSM_PIN:-1234}"
HSM_TOKEN_LABEL="${HSM_TOKEN_LABEL:-kms-master}"
softhsm2-util --init-token --slot 0 \
  --label "$HSM_TOKEN_LABEL" \
  --pin "$HSM_PIN" \
  --so-pin "$HSM_PIN" 2>/dev/null || echo "  (Token already exists — skipping)"

echo "  SoftHSM2 token '$HSM_TOKEN_LABEL' ready"

# Generate TLS certificates if not present
if [ ! -f "certs/server.crt" ]; then
  echo ""
  echo "==> Generating TLS certificates..."
  mkdir -p certs

  openssl genrsa -out certs/ca.key 4096 2>/dev/null
  openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
    -subj "/CN=KMS-CA/O=KMS/C=FR" 2>/dev/null

  openssl genrsa -out certs/server.key 2048 2>/dev/null
  openssl req -new -key certs/server.key -out /tmp/kms-server.csr \
    -subj "/CN=kms-server/O=KMS/C=FR" 2>/dev/null
  openssl x509 -req -days 365 -in /tmp/kms-server.csr \
    -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
    -out certs/server.crt \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null
  rm -f /tmp/kms-server.csr
  echo "  TLS certificates generated in ./certs/"
else
  echo "  TLS certificates already present"
fi

# Create .env from example
if [ ! -f ".env" ]; then
  cp .env.example .env
  sed -i "s|/usr/lib/softhsm/libsofthsm2.so|${SOFTHSM_LIB}|g" .env
  echo "  Created .env from .env.example"
  echo "  IMPORTANT: Edit .env and change SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD"
else
  echo "  .env already exists"
fi

echo ""
echo "==> Done! Start the KMS with:"
echo "    cd kms && PYTHONPATH=src python -m kms.main"
echo ""
echo "    Web UI:  http://localhost:8000"
echo "    API:     http://localhost:8000/api/v1/docs"
echo "    KMIP:    kmip://localhost:5696"
