import hashlib
import time
import logging
import os
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat, BestAvailableEncryption
from cryptography.exceptions import InvalidSignature


# ==================== 第一部分：PoW 工作量证明 ====================
def pow_calculate(nickname, target_leading_zeros, max_nonce=None, timeout=None, progress_interval=100000):
    """
    工作量证明核心函数：循环计算 sha256，直到哈希前缀满足指定数量的前导零
    :param nickname: 用户昵称
    :param target_leading_zeros: 目标前导零数量
    :param max_nonce: 可选，达到此 nonce 值则提前退出并返回 (None, last_hash, elapsed)
    :param timeout: 可选，以秒为单位，超过此耗时则提前退出并返回 (None, last_hash, elapsed)
    :return: 满足条件的 nonce、哈希值、耗时；如果超时或超出 max_nonce，返回 (None, last_hash_or_None, elapsed)
    """
    nonce = 0
    start_time = time.time()
    # get module logger
    logger = logging.getLogger(__name__)

    # immediate timeout shortcut
    if timeout is not None and timeout <= 0:
        return None, None, 0.0

    while True:
        # 拼接字符串：昵称 + nonce
        input_str = f"{nickname}#{nonce}"
        # 计算 sha256 哈希（返回字节类型，转换为十六进制字符串）
        hash_obj = hashlib.sha256(input_str.encode("utf-8"))
        hash_hex = hash_obj.hexdigest()
        # 计算前导零数量
        leading_zeros = len(hash_hex) - len(hash_hex.lstrip('0'))

        if leading_zeros >= target_leading_zeros:
            end_time = time.time()
            elapsed_time = end_time - start_time
            logger.info("【PoW 完成】目标：%d 个前导零", target_leading_zeros)
            logger.info("有效 Nonce：%d", nonce)
            logger.info("生成哈希：%s", hash_hex)
            logger.info("耗时：%.2f 秒", elapsed_time)
            return nonce, hash_hex, elapsed_time

        nonce += 1
        # 检查 max_nonce
        if max_nonce is not None and nonce >= max_nonce:
            end_time = time.time()
            elapsed_time = end_time - start_time
            logger.warning("【PoW】达到 max_nonce=%d，提前退出", max_nonce)
            return None, hash_hex, elapsed_time

        # 检查 timeout
        if timeout is not None:
            if time.time() - start_time >= timeout:
                end_time = time.time()
                elapsed_time = end_time - start_time
                logger.warning("【PoW】达到 timeout=%ss，提前退出", timeout)
                return None, hash_hex, elapsed_time
        # 可选：打印进度，避免程序看似卡住（高难度时建议保留）
        if progress_interval and nonce % progress_interval == 0:
            logger.debug("当前 nonce：%d，哈希：%s...，前导零：%d", nonce, hash_hex[:20], leading_zeros)


# ==================== 第二部分：RSA 非对称加密 ====================
def generate_rsa_key_pair(key_size=2048):
    """
    生成 RSA 公私钥对
    :param key_size: 密钥长度，2048 为常用安全长度，支持 1024/2048/4096
    :return: 私钥对象，公钥对象
    """
    print("\n【RSA】开始生成公私钥对...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    print(f"【RSA】公私钥对生成完成，密钥长度：{key_size} 位")
    return private_key, public_key


def export_private_key_encrypted(private_key, password: str, filename: str = "private_key.pem"):
    """
    将私钥以加密 PEM 的形式写入文件。若要安全保存私钥，请提供密码。
    :param private_key: 私钥对象
    :param password: 用于加密 PEM 的密码（字符串）
    :param filename: 输出文件路径
    :return: 写入的文件路径
    """
    logger = logging.getLogger(__name__)
    if not password:
        raise ValueError("password is required to export encrypted PEM")
    password_bytes = password.encode("utf-8")
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(password_bytes),
    )
    with open(filename, "wb") as f:
        f.write(pem)
    logger.info("已将私钥以加密 PEM 写入 %s", filename)
    return filename


def export_public_key(public_key, filename: str = "public_key.pem"):
    """将公钥写入 PEM 文件并返回路径。"""
    logger = logging.getLogger(__name__)
    pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    with open(filename, "wb") as f:
        f.write(pem)
    logger.info("已将公钥写入 %s", filename)
    return filename


def rsa_sign(private_key, data):
    """
    用私钥对数据进行签名
    :param private_key: 私钥对象
    :param data: 要签名的字符串
    :return: 签名结果（字节类型）
    """
    # 将字符串转换为字节，适配签名函数
    data_bytes = data.encode("utf-8")
    # 使用 PSS 填充方式签名，安全性高于 PKCS1v15
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def rsa_verify(public_key, data, signature):
    """
    用公钥验证签名的有效性
    :param public_key: 公钥对象
    :param data: 原始数据（字节类型）
    :param signature: 待验证的签名
    :return: 验证结果（布尔值）
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


# ==================== 主程序：整合所有流程 ====================
def main():
    # 自定义你的昵称（替换成你自己的名字即可）
    YOUR_NICKNAME = "jim123"

    # ====================== 步骤1：完成两次 PoW ======================
    print("=" * 60)
    print("开始执行 PoW 工作量证明任务")
    print("=" * 60)

    # 任务1：4 个前导零
    print("\n[任务1] 寻找满足 4 个前导零的 PoW...")
    nonce_4, hash_4, time_4 = pow_calculate(YOUR_NICKNAME, 4)

    # 任务2：5 个前导零（注意：难度提升，耗时会显著增加）
    print("\n[任务2] 寻找满足 5 个前导零的 PoW...")
    nonce_5, hash_5, time_5 = pow_calculate(YOUR_NICKNAME, 5)

    # ====================== 步骤2：RSA 非对称加密实践 ======================
    print("\n" + "=" * 60)
    print("开始执行 RSA 非对称加密任务")
    print("=" * 60)

    # 任务3：生成 RSA 公私钥对
    private_key, public_key = generate_rsa_key_pair()

    # 任务4&5：用私钥对“PoW 通过的字符串”签名（选择任意一个 PoW 结果即可，这里用 4 个前导零的结果）
    target_data = f"{YOUR_NICKNAME}#{nonce_4}"  # PoW 验证通过的字符串
    print(f"\n【RSA】待签名数据：{target_data}")
    signature = rsa_sign(private_key, target_data)
    print("【RSA】签名完成，签名结果（十六进制）：", signature.hex()[:60] + "...")

    # 任务6：用公钥验证签名
    print("\n【RSA】开始验证签名...")
    is_valid = rsa_verify(public_key, target_data.encode("utf-8"), signature)
    if is_valid:
        print("&#9989; 签名验证成功：签名有效，数据未被篡改")
    else:
        print("&#10060; 签名验证失败：签名无效或数据被篡改")

    # 可选：尝试伪造数据验证安全性
    print("\n【RSA】测试安全性：伪造数据验证...")
    fake_data = f"{YOUR_NICKNAME}#{nonce_4 + 1}"  # 篡改后的数据
    fake_is_valid = rsa_verify(public_key, fake_data.encode("utf-8"), signature)
    if not fake_is_valid:
        print("&#9989; 伪造数据验证失败，RSA 签名安全性得到验证")
    else:
        print("&#10060; 伪造数据验证通过，系统存在安全风险！")

    # CLI 参数解析：支持 --export (密码) 和 --export-path
    parser = argparse.ArgumentParser(description="PoW + RSA demo")
    parser.add_argument('--export', dest='export_password', help='密码：将私钥以加密 PEM 导出（优先于环境变量 POW_RSA_EXPORT_PW）')
    parser.add_argument('--export-path', dest='export_path', default='.', help='导出密钥的目录，默认当前目录')
    parser.add_argument('--debug', action='store_true', help='启用调试日志（显示进度）')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # 优先使用 CLI 参数，其次回退到环境变量（保持向后兼容）
    export_password = args.export_password or os.getenv("POW_RSA_EXPORT_PW")
    if export_password:
        try:
            priv_file = os.path.join(args.export_path, "private_key_encrypted.pem")
            pub_file = os.path.join(args.export_path, "public_key.pem")
            priv_path = export_private_key_encrypted(private_key, export_password, filename=priv_file)
            pub_path = export_public_key(public_key, filename=pub_file)
            print(f"\n[密钥已导出] 私钥(加密): {priv_path}  公钥: {pub_path}")
        except Exception as e:
            print(f"\n[密钥导出失败] {e}")


if __name__ == "__main__":
    main()
