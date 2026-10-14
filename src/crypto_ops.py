from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    ed25519,
    x25519,
)
from cryptography.hazmat.primitives import hashes


# ----------------------
# Key Generation
# ----------------------

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def generate_ecdsa_keypair():
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )
    return private_key, private_key.public_key()


def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()


# ----------------------
# Hashing
# ----------------------

def sha256_hash(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def sha3_256_hash(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(data)
    return digest.finalize()