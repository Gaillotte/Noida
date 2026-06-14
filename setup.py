from setuptools import setup, find_packages

setup(
    name="kmip_pkcs11",
    version="1.0.0",
    description="KMIP server implementation on top of PKCS#11 HSM",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "python-pkcs11>=0.7.0",
        "PyKCS11>=1.5.0",
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov"],
    },
)
