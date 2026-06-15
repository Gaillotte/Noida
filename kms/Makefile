.PHONY: help install init-softhsm init-db certs run dev stop clean test

PYTHON   ?= python3
PIP      ?= pip3
VENV     := .venv
HSM_PIN  ?= 1234
HSM_SO_PIN ?= 1234
HSM_TOKEN_LABEL ?= kms-master

help:
	@echo "KMS — Key Management System"
	@echo ""
	@echo "Targets:"
	@echo "  make install        Install Python dependencies"
	@echo "  make init-softhsm   Initialize SoftHSM2 token (run once)"
	@echo "  make certs          Generate self-signed CA + server TLS certs"
	@echo "  make init-db        Start PostgreSQL and create tables"
	@echo "  make init           Full initialization (install + softhsm + certs + db)"
	@echo "  make run            Start the KMS server"
	@echo "  make dev            Start in development mode (no TLS for KMIP)"
	@echo "  make stop           Stop Docker services"
	@echo "  make clean          Remove generated files and containers"
	@echo "  make test           Run tests"

install:
	$(PIP) install -r requirements.txt

init-softhsm:
	@echo "==> Initializing SoftHSM2 token '$(HSM_TOKEN_LABEL)'..."
	@mkdir -p /var/lib/softhsm/tokens 2>/dev/null || mkdir -p ~/.softhsm2/tokens
	softhsm2-util --init-token --slot 0 \
	  --label "$(HSM_TOKEN_LABEL)" \
	  --pin "$(HSM_PIN)" \
	  --so-pin "$(HSM_SO_PIN)" 2>/dev/null || echo "(Token may already exist — continuing)"
	@echo "==> SoftHSM2 token ready."

certs:
	@echo "==> Generating CA + server TLS certificates..."
	@mkdir -p certs
	@# CA key and cert
	openssl genrsa -out certs/ca.key 4096
	openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
	  -subj "/CN=KMS-CA/O=KMS/C=FR"
	@# Server key and CSR
	openssl genrsa -out certs/server.key 2048
	openssl req -new -key certs/server.key -out certs/server.csr \
	  -subj "/CN=kms-server/O=KMS/C=FR"
	@# Sign server cert with CA
	openssl x509 -req -days 365 -in certs/server.csr \
	  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
	  -out certs/server.crt \
	  -extfile <(echo "subjectAltName=DNS:localhost,DNS:kms-server,IP:127.0.0.1")
	@rm certs/server.csr
	@echo "==> Certificates generated in ./certs/"

init-db:
	@echo "==> Starting PostgreSQL..."
	docker-compose up -d postgres
	@echo "==> Waiting for PostgreSQL to be ready..."
	@for i in $$(seq 1 20); do \
	  docker-compose exec -T postgres pg_isready -U kms && break || sleep 2; \
	done
	@echo "==> PostgreSQL ready."

init: install init-softhsm certs init-db
	@echo ""
	@echo "==> KMS initialization complete!"
	@echo "==> Copy .env.example to .env and adjust settings, then run: make run"

run:
	@cp -n .env.example .env 2>/dev/null || true
	PYTHONPATH=src $(PYTHON) -m kms.main

dev:
	@echo "==> Starting in development mode (TLS disabled for KMIP)..."
	@cp -n .env.example .env 2>/dev/null || true
	PYTHONPATH=src KMS_TLS_CERT_FILE="" KMS_TLS_KEY_FILE="" KMS_TLS_CA_FILE="" \
	  $(PYTHON) -m kms.main

stop:
	docker-compose down

clean:
	docker-compose down -v
	rm -rf certs __pycache__ .venv
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

test:
	PYTHONPATH=src $(PYTHON) -m pytest tests/ -v
