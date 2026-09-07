# kmip-server container image.
#
# Two stages: the first builds SoftHSM2 from source, the second carries only
# the runtime. The build is not optional, and the version is the reason.
# SoftHSM2 2.6.1 — which is what Debian and Ubuntu package — does not expose
# the combined ECDSA-with-hash mechanisms (CKM_ECDSA_SHA256 and friends), so
# signing with an EC key fails against it. 2.7.0 does expose them. Verified by
# enumerating both mechanism lists on one machine: the packaged 2.6.1
# advertises 70 mechanisms without CKM_ECDSA_SHA256, a source-built 2.7.0
# advertises 79 with it. Note that the crypto backend is NOT the
# differentiator — the packaged build already links OpenSSL.
#
#   docker build -f deploy/Dockerfile -t kmip-server .
#   docker run --rm -v /etc/kmip:/etc/kmip:ro -v kmip-data:/var/lib/kmip \
#              -p 5696:5696 kmip-server

# ── stage 1: build SoftHSM2 with the OpenSSL backend ────────────────────────
FROM debian:bookworm-slim AS softhsm

ARG SOFTHSM_VERSION=2.7.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential automake autoconf libtool pkg-config \
        libssl-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://dist.opendnssec.org/source/softhsm-${SOFTHSM_VERSION}.tar.gz" \
        -o /tmp/softhsm.tar.gz \
    && tar -xzf /tmp/softhsm.tar.gz -C /tmp \
    && cd "/tmp/softhsm-${SOFTHSM_VERSION}" \
    && ./configure --prefix=/opt/softhsm --with-crypto-backend=openssl --disable-gost \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/softhsm*

# ── stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=softhsm /opt/softhsm /opt/softhsm
ENV SOFTHSM2_CONF=/etc/kmip/softhsm2.conf

WORKDIR /app
COPY setup.py README_KMIP.md ./
COPY kmip_pkcs11 ./kmip_pkcs11
RUN pip install --no-cache-dir .

# Unprivileged: the server needs its database and the token directory, nothing
# else. Both are volumes so they survive the container.
RUN useradd --system --create-home --home-dir /var/lib/kmip kmip \
    && mkdir -p /var/lib/kmip /etc/kmip \
    && chown -R kmip:kmip /var/lib/kmip
USER kmip

VOLUME ["/var/lib/kmip"]
EXPOSE 5696 9696

# The health endpoint is the right liveness signal: it answers only once the
# process is actually serving.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9696/health', timeout=2).status==200 else 1)"

ENTRYPOINT ["kmip-server"]
CMD ["--config", "/etc/kmip/config.yaml"]
