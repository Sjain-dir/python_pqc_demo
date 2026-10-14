from src.crypto_ops import (
    generate_rsa_keypair,
    generate_ecdsa_keypair,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    sha256_hash,
    sha3_256_hash,
)


def test_rsa_keypair():
    priv, pub = generate_rsa_keypair()

    assert priv is not None
    assert pub is not None


def test_ecdsa_keypair():
    priv, pub = generate_ecdsa_keypair()

    assert priv is not None
    assert pub is not None


def test_ed25519_keypair():
    priv, pub = generate_ed25519_keypair()

    assert priv is not None
    assert pub is not None


def test_x25519_keypair():
    priv, pub = generate_x25519_keypair()

    assert priv is not None
    assert pub is not None


def test_sha256():
    digest = sha256_hash(b"hello world")

    assert len(digest) == 32


def test_sha3_256():
    digest = sha3_256_hash(b"hello world")

    assert len(digest) == 32