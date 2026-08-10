from setuptools import setup, find_packages

setup(
    name="kmip_pkcs11",
    version="1.0.0",
    description="KMIP server implementation on top of PKCS#11 HSM",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        # Floor raised from >=0.7.0 to the version the code is actually tested
        # against. The shim depends on 0.9.x behaviour, and a lower floor lets
        # a fresh install resolve to something that has never been exercised.
        "python-pkcs11>=0.9.5",
        # PyKCS11 was listed here but is imported by no module in the package —
        # everything uses python-pkcs11 (`import pkcs11`). Keeping it forced a
        # C toolchain into every deployment image to build an extension that is
        # never loaded.
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov"],
    },
)
