from setuptools import setup, find_packages

setup(
    name="kmip_pkcs11",
    version="1.0.0",
    description="KMIP server implementation on top of PKCS#11 HSM",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        # Pinned: the shim relies on 0.9.x call signatures (unwrap_key's
        # positional object_class, Session.digest). 0.7.0 fails at runtime.
        # PyKCS11 was previously listed here but is imported nowhere in the
        # codebase — python-pkcs11 is the only PKCS#11 binding used.
        "python-pkcs11>=0.9.5,<0.10",
        # Configuration files. Only the safe loader is used.
        "PyYAML>=5.4",
        # asn1crypto builds and parses X.509 for Certify/ReCertify/Validate and
        # encodes RSA key material — the `cryptography` package is deliberately
        # not a dependency, since all actual crypto happens on the HSM.
        "asn1crypto>=1.4",
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov", "pytest-timeout"],
    },
    entry_points={
        "console_scripts": [
            "kmip-server=kmip_pkcs11.cli.server_cli:main",
            "kmip-admin=kmip_pkcs11.cli.admin_cli:main",
        ],
    },
)
