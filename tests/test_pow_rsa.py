import sys
import pathlib
import pytest

# ensure project root is on sys.path so tests can import pow_rsa
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from pow_rsa import pow_sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def test_pow_sha256_easy():
    # use low difficulty so test runs quickly
    nonce, h = pow_sha256("unittest", 1)
    assert isinstance(nonce, int)
    assert h.startswith("0")


def test_rsa_sign_verify():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    message = b"testmessage"
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    # should not raise
    public_key.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
