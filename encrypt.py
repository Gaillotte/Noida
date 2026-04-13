#!/usr/bin/env python3
"""
Outil de chiffrement de fichier AES-256-CBC en ligne de commande.

Utilisation :
    python encrypt.py <fichier_à_chiffrer>

Fichier de sortie : <nom_original>_<nb_octets_padding>.cif
Format interne   : IV (16 octets) | données chiffrées

Aucune dépendance externe : utilise OpenSSL (libcrypto) via ctypes.
"""

import sys
import os
import ctypes
import ctypes.util

# ---------------------------------------------------------------------------
# Clé AES-256 fixe (32 octets = 256 bits)
# ATTENTION : ne jamais exposer cette clé dans un vrai déploiement.
# ---------------------------------------------------------------------------
AES_KEY: bytes = (
    b'\x4a\x7f\x2c\x9e\xb1\x05\xd8\x3a'
    b'\xfe\x62\x19\x74\x0b\xcc\x87\x5d'
    b'\x33\xaa\xe6\x1f\x90\x2b\x4d\x08'
    b'\x7c\x51\xf3\xbd\x29\x6e\xa4\x0c'
)  # 32 octets

BLOCK_SIZE: int = 16  # taille de bloc AES en octets


# ---------------------------------------------------------------------------
# Chargement et configuration de libcrypto (OpenSSL)
# ---------------------------------------------------------------------------

def _load_libcrypto() -> ctypes.CDLL:
    lib_name = ctypes.util.find_library('crypto')
    if lib_name is None:
        raise RuntimeError(
            "libcrypto (OpenSSL) introuvable sur ce système. "
            "Installez openssl (ex. : apt install libssl-dev)."
        )
    lc = ctypes.CDLL(lib_name)

    # EVP_CIPHER_CTX_new / EVP_CIPHER_CTX_free
    lc.EVP_CIPHER_CTX_new.restype  = ctypes.c_void_p
    lc.EVP_CIPHER_CTX_new.argtypes = []
    lc.EVP_CIPHER_CTX_free.restype  = None
    lc.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

    # EVP_aes_256_cbc
    lc.EVP_aes_256_cbc.restype  = ctypes.c_void_p
    lc.EVP_aes_256_cbc.argtypes = []

    # EVP_EncryptInit_ex
    lc.EVP_EncryptInit_ex.restype  = ctypes.c_int
    lc.EVP_EncryptInit_ex.argtypes = [
        ctypes.c_void_p,   # ctx
        ctypes.c_void_p,   # type (cipher)
        ctypes.c_void_p,   # impl (engine – NULL)
        ctypes.c_char_p,   # key
        ctypes.c_char_p,   # iv
    ]

    # EVP_CIPHER_CTX_set_padding  (0 = désactiver le padding OpenSSL)
    lc.EVP_CIPHER_CTX_set_padding.restype  = ctypes.c_int
    lc.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]

    # EVP_EncryptUpdate
    lc.EVP_EncryptUpdate.restype  = ctypes.c_int
    lc.EVP_EncryptUpdate.argtypes = [
        ctypes.c_void_p,                    # ctx
        ctypes.c_char_p,                    # out
        ctypes.POINTER(ctypes.c_int),       # outl
        ctypes.c_char_p,                    # in
        ctypes.c_int,                       # inl
    ]

    # EVP_EncryptFinal_ex
    lc.EVP_EncryptFinal_ex.restype  = ctypes.c_int
    lc.EVP_EncryptFinal_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
    ]

    return lc


_libcrypto = _load_libcrypto()


# ---------------------------------------------------------------------------
# Padding PKCS7 (1 à 16 octets ajoutés, jamais 0)
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes) -> tuple[bytes, int]:
    """
    Aligne *data* sur BLOCK_SIZE avec un padding PKCS7.

    Retourne (données_paddées, nb_octets_de_padding).
    Le padding est toujours compris entre 1 et BLOCK_SIZE inclus.
    """
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    if padding_len == 0:
        padding_len = BLOCK_SIZE  # ajouter un bloc entier si déjà aligné
    return data + bytes([padding_len] * padding_len), padding_len


# ---------------------------------------------------------------------------
# Chiffrement AES-256-CBC (OpenSSL via ctypes)
# ---------------------------------------------------------------------------

def aes256_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Chiffre *plaintext* (déjà aligné sur 16 octets) avec AES-256-CBC.
    Le padding OpenSSL est désactivé : on gère le padding manuellement.
    """
    lc  = _libcrypto
    ctx = lc.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new a échoué.")

    try:
        if lc.EVP_EncryptInit_ex(ctx, lc.EVP_aes_256_cbc(), None, key, iv) != 1:
            raise RuntimeError("EVP_EncryptInit_ex a échoué.")

        # Désactiver le padding automatique (on fournit des données déjà alignées)
        if lc.EVP_CIPHER_CTX_set_padding(ctx, 0) != 1:
            raise RuntimeError("EVP_CIPHER_CTX_set_padding a échoué.")

        out_buf = ctypes.create_string_buffer(len(plaintext) + BLOCK_SIZE)
        out_len = ctypes.c_int(0)

        if lc.EVP_EncryptUpdate(ctx, out_buf, ctypes.byref(out_len),
                                plaintext, len(plaintext)) != 1:
            raise RuntimeError("EVP_EncryptUpdate a échoué.")

        total = out_len.value

        fin_buf = ctypes.create_string_buffer(BLOCK_SIZE)
        fin_len = ctypes.c_int(0)

        if lc.EVP_EncryptFinal_ex(ctx, fin_buf, ctypes.byref(fin_len)) != 1:
            raise RuntimeError("EVP_EncryptFinal_ex a échoué.")

        return out_buf.raw[:total] + fin_buf.raw[:fin_len.value]

    finally:
        lc.EVP_CIPHER_CTX_free(ctx)


# ---------------------------------------------------------------------------
# Chiffrement d'un fichier
# ---------------------------------------------------------------------------

def encrypt_file(input_path: str) -> None:
    """Chiffre le fichier *input_path* et écrit le résultat dans un .cif."""

    # Lecture du fichier source
    with open(input_path, 'rb') as fh:
        plaintext = fh.read()

    # Padding PKCS7
    padded, padding_len = pkcs7_pad(plaintext)

    # IV aléatoire (16 octets)
    iv = os.urandom(BLOCK_SIZE)

    # Chiffrement
    ciphertext = aes256_cbc_encrypt(AES_KEY, iv, padded)

    # Nom de sortie : <nom_fichier_original>_<padding>.cif
    base_name   = os.path.basename(input_path)
    output_name = f"{base_name}_{padding_len}.cif"
    output_dir  = os.path.dirname(os.path.abspath(input_path))
    output_path = os.path.join(output_dir, output_name)

    # Écriture : IV (16 octets) | texte chiffré
    with open(output_path, 'wb') as fh:
        fh.write(iv)
        fh.write(ciphertext)

    print(f"Fichier source    : {input_path}  ({len(plaintext)} octets)")
    print(f"Padding ajouté    : {padding_len} octet(s)")
    print(f"Fichier chiffré   : {output_path}  ({os.path.getsize(output_path)} octets)")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage : python {sys.argv[0]} <fichier_à_chiffrer>")
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.isfile(input_file):
        print(f"Erreur : '{input_file}' n'existe pas ou n'est pas un fichier.")
        sys.exit(1)

    encrypt_file(input_file)


if __name__ == '__main__':
    main()
