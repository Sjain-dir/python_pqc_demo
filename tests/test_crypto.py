from src.crypto_ops import (
    mldsa_sign_verify,
    mlkem_exchange,
    generate_rsa_keypair,
    ed25519_sign_verify,
    sha256_hash,
    sha3_256_hash,
)


def test_mldsa():
    sig = mldsa_sign_verify()
    assert len(sig) > 0


def test_mlkem():
    secret = mlkem_exchange()
    assert len(secret) > 0


def test_rsa():
    private_key, public_key = generate_rsa_keypair()

    assert private_key is not None
    assert public_key is not None


def test_ed25519():
    signature = ed25519_sign_verify()

    assert len(signature) > 0


def test_sha256():
    digest = sha256_hash(b"hello")
    assert len(digest) == 64


def test_sha3():
    digest = sha3_256_hash(b"hello")
    assert len(digest) == 64