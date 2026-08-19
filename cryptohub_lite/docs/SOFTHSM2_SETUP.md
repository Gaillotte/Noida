# SoftHSM2 Setup

SoftHSM2 is a software PKCS#11 token. It lets the whole platform run — and its
tests pass — with no physical HSM, which is a stated requirement.

## The one thing to know first

**Use SoftHSM2 from master (2.7.0), not the 2.6.1 release.**

The engine signs EC with `CKM_ECDSA_SHA256/384/512`. Those mechanisms do not
exist in the 2.6.1 release. Measured by listing each build's mechanisms:

| Build | ECDSA mechanisms offered |
|---|---|
| 2.6.1, Botan backend (the distro package) | `ECDSA` |
| 2.6.1, OpenSSL backend (source) | `ECDSA` |
| **2.7.0, master (source)** | `ECDSA`, `ECDSA-SHA1`, `ECDSA-SHA224`, **`ECDSA-SHA256`**, **`ECDSA-SHA384`**, **`ECDSA-SHA512`** |

On 2.6.1 — *either* backend — EC signing fails with `MechanismInvalid` and **8
of the tests fail**. No configuration changes that; the release simply does
not implement the mechanisms.

> The crypto backend is a red herring here. It is easy to assume Botan is the
> problem, because the fixture comment in `conftest.py` says
> `# OpenSSL build — supports ECDSA_SHA*` and points at `/usr/local/lib`,
> where a source build installs. The path is right and the reason is wrong:
> what that source build supplied was a *newer version*, not a different
> backend. This was verified by building both and comparing mechanism lists,
> after an OpenSSL 2.6.1 build failed the same 8 tests.

OpenSSL is still preferred over Botan for broader algorithm coverage
generally — just don't expect it to supply ECDSA-SHA on 2.6.1.

### Consequence for the README's claim

`README.md` states that the suite passes in full — **811 tests** as of the
phases 0–5 sync. That is reproducible only on a SoftHSM2 new enough to offer the
combined ECDSA mechanisms. On 2.6.1 the EC signing tests fail (8 of them, when
the count was 624). The tests are correct and so is the shim, which refuses a
mechanism the token lacks rather than failing deep inside the binding.

## Docker (what the stack does)

`cryptohub_lite/docker/Dockerfile.api` builds it in a first stage:

```dockerfile
ARG SOFTHSM_REF=master
RUN git clone --depth 1 --branch ${SOFTHSM_REF} https://github.com/opendnssec/SoftHSMv2.git /tmp/softhsm \
    && cd /tmp/softhsm && sh autogen.sh \
    && ./configure --with-crypto-backend=openssl --disable-gost \
    && make -j"$(nproc)" && make install
```

Pin `SOFTHSM_REF` to a commit for a reproducible image — this is the layer
that decides which mechanisms exist.

Only the module and `softhsm2-util` are copied into the runtime image. This is
why the first build takes a few minutes; nothing else needs doing.

## Local install (for running tests outside Docker)

```bash
sudo apt-get install -y build-essential automake autoconf libtool pkg-config libssl-dev git
git clone --depth 1 https://github.com/opendnssec/SoftHSMv2.git   # master
cd SoftHSMv2 && sh autogen.sh
./configure --with-crypto-backend=openssl --disable-gost
make -j"$(nproc)" && sudo make install
```

Confirm the backend:

```bash
softhsm2-util --version
ls -l /usr/local/lib/softhsm/libsofthsm2.so
```

## Configuration

`SOFTHSM2_CONF` points at the configuration; the container entrypoint writes:

```ini
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend  = file
log.level            = ERROR
slots.removable      = false
```

`slots.removable = false` keeps uninitialised slots visible to
`C_GetSlotList`, which is what lets the PKCS#11 Explorer show a spare slot as
available capacity rather than hiding it.

## Initialising a token

```bash
softhsm2-util --init-token --free --label CryptoHubLite --pin 1234 --so-pin 4321
```

**Check before creating.** SoftHSM2 does *not* reject a duplicate label — it
creates a second token with the same name, and `--free` happily takes the next
empty slot. Re-running an init script therefore multiplies tokens on every
start, and a label is the token's identity, so "the CryptoHubLite token"
becomes ambiguous. The entrypoint guards against this:

```sh
existing=$(softhsm2-util --show-slots | sed -n 's/^ *Label: *//p' | sed 's/ *$//')
if echo "$existing" | grep -qx "$TOKEN_LABEL"; then
    echo "already initialised"
else
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$PIN" --so-pin "$SO_PIN"
fi
```

## Inspecting a token

```bash
softhsm2-util --show-slots
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login --pin 1234 --list-objects
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --list-mechanisms | grep -i ecdsa
```

The last one is the quickest way to tell builds apart: 2.7.0 lists
`ECDSA-SHA256`; 2.6.1 lists only `ECDSA`, whichever backend it was built
with.

In the running stack, the **PKCS#11 Explorer** page shows the same information
without a shell.

## Where the token lives

The `chl_tokens` Docker volume, mounted at `/var/lib/softhsm/tokens` in both
the API and KMIP containers — they share one token deliberately, so a key
created through either interface is the same object.

```bash
docker volume inspect cryptohub-lite_chl_tokens
docker compose -f cryptohub_lite/docker-compose.yml down -v   # destroys all keys
```

## Limitations to be explicit about

SoftHSM2 is **not FIPS 140-2/3 or Common Criteria validated**, and its "HSM
boundary" is a directory on disk. It is correct for development and CI, and it
is not a production key store. Moving to validated hardware is a configuration
change — see [PKCS11_INTEGRATION.md](PKCS11_INTEGRATION.md).
