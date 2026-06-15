from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://kms:kms_secret@localhost:5432/kms"

    # Security
    secret_key: str = "insecure-dev-key-change-in-production"
    access_token_expire_minutes: int = 60

    # PKCS#11 / SoftHSM2
    pkcs11_lib: str = "/usr/lib/softhsm/libsofthsm2.so"
    pkcs11_token_label: str = "kms-master"
    pkcs11_pin: str = "1234"

    # Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    kmip_host: str = "0.0.0.0"
    kmip_port: int = 5696

    # TLS for KMIP
    tls_cert_file: str = "certs/server.crt"
    tls_key_file: str = "certs/server.key"
    tls_ca_file: str = "certs/ca.crt"

    # Bootstrap admin
    bootstrap_admin_user: str = "admin"
    bootstrap_admin_password: str = "admin"

    # Logging
    log_level: str = "INFO"

    # KEK label in HSM — master key encryption key
    kek_label: str = "kms-kek-v1"
    kek_id: bytes = b"\x00\x01"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
