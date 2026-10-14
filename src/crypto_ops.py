import hashlib
import oqs


# ----------------------
# Signature Algorithms
# ----------------------

def generate_mldsa_keypair():
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    return public_key, secret_key


def generate_falcon_keypair():
    with oqs.Signature("Falcon-512") as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    return public_key, secret_key


# ----------------------
# KEM Algorithms
# ----------------------

def generate_mlkem_keypair():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    return public_key, secret_key


def generate_hqc_keypair():
    with oqs.KeyEncapsulation("HQC-192") as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    return public_key, secret_key


# ----------------------
# Hashing
# ----------------------

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha3_256_hash(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()