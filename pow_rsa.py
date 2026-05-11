import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

NICKNAME = "jim123"


# ========== 1. SHA256 POW ==========
def pow_sha256(nickname, leading_zeros):
    prefix = "0" * leading_zeros
    nonce = 0
    while True:
        data = f"{nickname}{nonce}".encode()
        h = hashlib.sha256(data).hexdigest()
        if h.startswith(prefix):
            return nonce, h
        nonce += 1


if __name__ == "__main__":
    for zeros in (4, 5):
        start = time.time()
        nonce, hash_result = pow_sha256(NICKNAME, zeros)
        elapsed = time.time() - start
        print(f"[POW] {zeros} 个 0 开头 | nonce={nonce} | hash={hash_result} | 耗时={elapsed:.4f}s")


    # ========== 2. RSA 非对称加密 ==========
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # ========== 3. 私钥签名 ==========
    message = f"{NICKNAME}{nonce}".encode()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print(f"\n[RSA] 签名完成 | 签名(hex)={signature.hex()[:60]}...")

    # ========== 4. 公钥验证 ==========
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("[RSA] 公钥验证成功，签名有效！")
    except Exception:
        print("[RSA] 公钥验证失败！")

    # 打印密钥信息
    print(f"\n[密钥信息]")
    print(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode())
    print(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode())
