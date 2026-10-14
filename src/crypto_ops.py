import hashlib

# Classical
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ed25519,
)

# PQC (cryptography 47+)
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA65PrivateKey,
)


# --------------------
# ML-DSA
# --------------------

def mldsa_sign_verify():
    private_key = MLDSA65PrivateKey.generate()
    public_key = private_key.public_key()

    message = b"hello world"
    context = b"test"

    signature = private_key.sign(message, context)

    public_key.verify(signature, message, context)

    return signature


# --------------------
# ML-KEM
# --------------------

def mlkem_exchange():
    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()

    sender_secret, ciphertext = public_key.encapsulate()

    receiver_secret = private_key.decapsulate(ciphertext)

    assert sender_secret == receiver_secret

    return sender_secret


# --------------------
# RSA
# --------------------

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    return private_key, private_key.public_key()


# --------------------
# Ed25519
# --------------------

def ed25519_sign_verify():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    message = b"hello"

    signature = private_key.sign(message)

    public_key.verify(signature, message)

    return signature


# --------------------
# Hashes
# --------------------

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha3_256_hash(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()