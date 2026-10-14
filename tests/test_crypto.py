from src.crypto_ops import (
    generate_mldsa_keypair,
    generate_mlkem_keypair,
    generate_falcon_keypair,
    generate_hqc_keypair,
    sha256_hash,
    sha3_256_hash,
)


def test_mldsa_keypair():
    pub, priv = generate_mldsa_keypair()

    assert pub is not None
    assert priv is not None
    assert len(pub) > 0
    assert len(priv) > 0


def test_mlkem_keypair():
    pub, priv = generate_mlkem_keypair()

    assert pub is not None
    assert priv is not None
    assert len(pub) > 0
    assert len(priv) > 0


def test_falcon_keypair():
    pub, priv = generate_falcon_keypair()

    assert pub is not None
    assert priv is not None
    assert len(pub) > 0
    assert len(priv) > 0


def test_hqc_keypair():
    pub, priv = generate_hqc_keypair()

    assert pub is not None
    assert priv is not None
    assert len(pub) > 0
    assert len(priv) > 0


def test_sha256():
    digest = sha256_hash(b"hello world")

    assert len(digest) == 64
    assert digest == (
        "b94d27b9934d3e08a52e52d7da7dabfa"
        "c484efe37a5380ee9088f7ace2efcde9"
    )


def test_sha3_256():
    digest = sha3_256_hash(b"hello world")

    assert len(digest) == 64