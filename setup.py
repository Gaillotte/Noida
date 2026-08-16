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
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov"],
    },
)
