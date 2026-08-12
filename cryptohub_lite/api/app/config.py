"""Configuration for the CryptoHub Lite API, from environment variables."""

import os


class Settings:
    """Runtime configuration.

    Everything is environment-driven so the same image runs under Docker
    Compose and under XAMPP-style local development without a rebuild.
    """

    # Metadata store. Accepts a postgresql:// DSN or a SQLite path — the same
    # string MetadataStore takes, so the API and the KMIP server can be
    # pointed at one store.
    database_url: str = os.getenv(
        "CRYPTOHUB_DB",
        "postgresql://cryptohub:devpass@postgres:5432/cryptohub",
    )

    # PKCS#11 module. Defaults to the SoftHSM2 build the container installs.
    pkcs11_library: str = os.getenv("SOFTHSM2_LIB", "/usr/local/lib/softhsm/libsofthsm2.so")
    pkcs11_token: str = os.getenv("PKCS11_TOKEN", "CryptoHubLite")
    pkcs11_pin: str = os.getenv("PKCS11_PIN", "1234")

    # JWT signing. A generated default keeps development frictionless; the
    # API refuses to start in production mode without an explicit secret,
    # because a rotating key silently invalidates every issued token.
    jwt_secret: str = os.getenv("JWT_SECRET", "dev-only-change-me")
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = int(os.getenv("JWT_TTL_MINUTES", "480"))

    # Seed administrator, created once if no users exist at all.
    #
    # The default meets the 8-character minimum the API enforces on every
    # other password. It previously did not ("admin", 5 characters), which
    # meant the shipped default could not be re-entered through any normal
    # path — an administrator who changed it could never set it back, and the
    # system was contradicting a rule it enforces on everyone else.
    bootstrap_admin: str = os.getenv("BOOTSTRAP_ADMIN", "admin")
    bootstrap_password: str = os.getenv("BOOTSTRAP_PASSWORD", "admin123")

    cors_origins: list = (os.getenv("CORS_ORIGINS", "*")).split(",")

    @property
    def is_production(self) -> bool:
        return os.getenv("CRYPTOHUB_ENV", "development").lower() == "production"


settings = Settings()
