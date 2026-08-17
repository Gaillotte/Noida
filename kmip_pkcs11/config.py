"""Configuration loading for the KMIP server.

Everything the server needs to run comes from a YAML file, so a deployment is
a config file plus a service unit rather than a Python script. See
deploy/config.example.yaml for an annotated template.

The token PIN gets special treatment. It is the credential that unlocks the
HSM, so it should arrive from a file mounted by a secrets manager or from the
environment — never sit in a config file that ends up in version control.
Putting it inline still works, because forbidding it outright would just push
people to hardcode it somewhere worse, but it logs a warning every start.
"""

import logging
import os
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

DEFAULTS: Dict[str, Any] = {
    "server": {
        "host": "127.0.0.1",
        "port": 5696,
        "max_request_size": 1024 * 1024,
        "handshake_timeout": 10.0,
        "allow_plaintext": False,
        # 1 keeps everything in one process. Higher forks that many workers,
        # each with its own PKCS#11 session, which is the only way past the
        # single-session throughput ceiling. null means one per CPU.
        "workers": 1,
    },
    "tls": {
        "cert": None,
        "key": None,
        "ca": None,
        "require_client_cert": False,
    },
    "hsm": {
        "library": None,
        "token_label": None,
        "pin": None,
        "pin_file": None,
        "pin_env": None,
    },
    "storage": {
        "database": "/var/lib/kmip/kmip.db",
    },
    "observability": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 9696,
    },
    "logging": {
        "level": "INFO",
        "format": "json",
    },
}


class ConfigError(Exception):
    """Raised for a malformed or incomplete configuration. Always names the
    offending key, because a config error at boot should be self-explanatory."""


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Two-level merge — deep enough for this schema, and it keeps unknown
    keys so validation can complain about them by name."""
    merged = {k: dict(v) if isinstance(v, dict) else v for k, v in base.items()}
    for section, values in (override or {}).items():
        if isinstance(values, dict) and isinstance(merged.get(section), dict):
            merged[section].update(values)
        else:
            merged[section] = values
    return merged


class KMIPConfig:
    def __init__(self, data: Dict[str, Any]):
        self._data = _merge(DEFAULTS, data or {})
        self._validate()

    # ── loading ─────────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str) -> "KMIPConfig":
        try:
            import yaml
        except ImportError as e:  # pragma: no cover - dependency is declared
            raise ConfigError("PyYAML is required to read a configuration file") from e

        if not os.path.exists(path):
            raise ConfigError(f"Configuration file not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            raise ConfigError(f"Could not parse {path}: {e}") from e
        if data is not None and not isinstance(data, dict):
            raise ConfigError(f"{path} must contain a YAML mapping at the top level")
        return cls(data or {})

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KMIPConfig":
        return cls(data)

    # ── access ──────────────────────────────────────────────────────────────

    def section(self, name: str) -> Dict[str, Any]:
        return self._data.get(name, {})

    def get(self, section: str, key: str, default=None):
        return self._data.get(section, {}).get(key, default)

    def as_dict(self) -> Dict[str, Any]:
        """A copy safe to log or print: the inline PIN is redacted, since the
        most likely reason to dump the config is to paste it into a bug report."""
        safe = {k: dict(v) if isinstance(v, dict) else v for k, v in self._data.items()}
        if safe.get("hsm", {}).get("pin"):
            safe["hsm"]["pin"] = "***redacted***"
        return safe

    # ── validation ──────────────────────────────────────────────────────────

    def _validate(self):
        unknown = set(self._data) - set(DEFAULTS)
        if unknown:
            raise ConfigError(f"Unknown configuration section(s): {', '.join(sorted(unknown))}")

        for required, section in (("library", "hsm"), ("token_label", "hsm")):
            if not self.get(section, required):
                raise ConfigError(f"{section}.{required} is required")

        if not self.get("storage", "database"):
            raise ConfigError("storage.database is required")

        port = self.get("server", "port")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ConfigError(f"server.port must be a port number, got {port!r}")

        # TLS: a certificate without its key (or vice versa) is a
        # half-configured deployment that would fail at the first connection.
        cert, key = self.get("tls", "cert"), self.get("tls", "key")
        if bool(cert) != bool(key):
            raise ConfigError("tls.cert and tls.key must be set together")
        if not cert and not self.get("server", "allow_plaintext"):
            raise ConfigError(
                "No TLS certificate configured. Set tls.cert and tls.key, or set "
                "server.allow_plaintext: true to serve KMIP unencrypted deliberately"
            )
        if self.get("tls", "require_client_cert") and not self.get("tls", "ca"):
            raise ConfigError("tls.require_client_cert needs tls.ca to verify against")

        sources = [k for k in ("pin_file", "pin_env", "pin") if self.get("hsm", k)]
        if not sources:
            raise ConfigError("One of hsm.pin_file, hsm.pin_env or hsm.pin is required")
        if len(sources) > 1:
            raise ConfigError(
                f"Set only one of hsm.pin_file, hsm.pin_env, hsm.pin — found {', '.join(sources)}"
            )

        workers = self.get("server", "workers")
        if workers is not None and (not isinstance(workers, int) or workers < 1):
            raise ConfigError(
                f"server.workers must be a positive integer or null (one per CPU), "
                f"got {workers!r}")

        fmt = self.get("logging", "format")
        if fmt not in ("json", "text"):
            raise ConfigError(f"logging.format must be 'json' or 'text', got {fmt!r}")

    # ── secrets ─────────────────────────────────────────────────────────────

    def resolve_pin(self) -> str:
        """Read the token PIN from whichever source was configured.

        Kept out of __init__ deliberately: the PIN is fetched at the moment it
        is needed rather than held on the config object, so dumping or logging
        the configuration cannot leak it."""
        pin_file = self.get("hsm", "pin_file")
        if pin_file:
            if not os.path.exists(pin_file):
                raise ConfigError(f"hsm.pin_file not found: {pin_file}")
            try:
                with open(pin_file, "r", encoding="utf-8") as f:
                    pin = f.read().strip()
            except OSError as e:
                raise ConfigError(f"Could not read hsm.pin_file {pin_file}: {e}") from e
            if not pin:
                raise ConfigError(f"hsm.pin_file is empty: {pin_file}")
            return pin

        pin_env = self.get("hsm", "pin_env")
        if pin_env:
            pin = os.environ.get(pin_env)
            if not pin:
                raise ConfigError(f"Environment variable {pin_env} is unset or empty")
            return pin

        log.warning(
            "HSM PIN is set inline in the configuration file. Prefer hsm.pin_file "
            "(mounted by a secrets manager) or hsm.pin_env so the PIN never sits "
            "in a file that can be committed to version control."
        )
        return self.get("hsm", "pin")
