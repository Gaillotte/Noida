#!/bin/sh
# Prepares the SoftHSM2 token, then starts the requested service.
#
# Token creation is idempotent: --init-token is only run when no token with
# the configured label exists. SoftHSM2 does not reject a duplicate label —
# it happily creates a second token with the same name — so re-running this
# without the check would multiply tokens on every container start.
set -e

TOKEN_LABEL="${PKCS11_TOKEN:-CryptoHubLite}"
PIN="${PKCS11_PIN:-1234}"
SO_PIN="${PKCS11_SO_PIN:-4321}"

mkdir -p /var/lib/softhsm/tokens
cat > /etc/softhsm2.conf <<CONF
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
CONF

existing=$(softhsm2-util --show-slots 2>/dev/null | sed -n 's/^ *Label: *//p' | sed 's/ *$//')
if echo "$existing" | grep -qx "$TOKEN_LABEL"; then
    echo "[entrypoint] token '$TOKEN_LABEL' already initialised"
else
    echo "[entrypoint] initialising token '$TOKEN_LABEL'"
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
                  --pin "$PIN" --so-pin "$SO_PIN"
fi

case "${SERVICE:-api}" in
    kmip)
        echo "[entrypoint] starting KMIP server on :5696"
        exec python -m app.kmip_server_main
        ;;
    *)
        echo "[entrypoint] starting REST API on :8000"
        exec uvicorn app.main:app --host 0.0.0.0 --port 8000
        ;;
esac
