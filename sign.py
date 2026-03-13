'''
实践非对称加密 RSA（编程语言不限）：

先生成一个公私钥对
用私钥对符合 POW 4 个 0 开头的哈希值的 “昵称 + nonce” 进行私钥签名
用公钥验证
'''
import hashlib
import os
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto import Random


class RSASignatureSystem:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """生成RSA公私钥对"""
        random_generator = Random.new().read
        key = RSA.generate(self.key_size, random_generator)

        self.private_key = key
        self.public_key = key.publickey()

        return {
            'private_key': key.export_key().decode('utf-8'),
            'public_key': key.publickey().export_key().decode('utf-8')
        }

    def find_pow_nonce(self, nickname, difficulty=4):
        """
        工作量证明：寻找符合条件的nonce
        要求：SHA256(nickname + nonce) 以指定数量的0开头
        """
        target_prefix = '0' * difficulty
        nonce = 0

        while True:
            message = f"{nickname}{nonce}"
            message_hash = hashlib.sha256(message.encode()).hexdigest()

            if message_hash.startswith(target_prefix):
                return nonce, message_hash

            nonce += 1

    def sign_with_private_key(self, nickname, nonce):
        """使用私钥对消息进行签名"""
        if not self.private_key:
            raise ValueError("未生成私钥")

        # 构造消息
        message = f"{nickname}{nonce}"

        # 计算消息的哈希
        message_hash = SHA256.new(message.encode())

        # 使用私钥签名
        signature = pkcs1_15.new(self.private_key).sign(message_hash)

        return signature.hex()

    def verify_with_public_key(self, nickname, nonce, signature_hex):
        """使用公钥验证签名"""
        if not self.public_key:
            raise ValueError("未生成公钥")

        # 构造消息
        message = f"{nickname}{nonce}"

        # 计算消息的哈希
        message_hash = SHA256.new(message.encode())

        # 从十六进制恢复签名
        signature = bytes.fromhex(signature_hex)

        try:
            # 验证签名
            pkcs1_15.new(self.public_key).verify(message_hash, signature)
            return True
        except (ValueError, TypeError):
            return False

    def demo_workflow(self, nickname="Alice"):
        """演示完整的工作流程"""
        print("=" * 60)
        print("RSA非对称加密签名系统演示")
        print("=" * 60)

        # 1. 生成密钥对
        print("\n1. 生成RSA公私钥对...")
        keys = self.generate_keypair()
        print(f"私钥长度: {len(keys['private_key'])} 字符")
        print(f"公钥长度: {len(keys['public_key'])} 字符")

        # 2. 工作量证明
        print("\n2. 执行工作量证明（POW）...")
        print(f"目标：SHA256('{nickname}' + nonce) 以4个0开头")
        nonce, message_hash = self.find_pow_nonce(nickname, difficulty=4)
        print(f"找到符合条件的nonce: {nonce}")
        print(f"消息: {nickname}{nonce}")
        print(f"哈希值: {message_hash}")

        # 3. 使用私钥签名
        print("\n3. 使用私钥对消息进行签名...")
        signature = self.sign_with_private_key(nickname, nonce)
        print(f"签名结果: {signature[:50]}...")

        # 4. 使用公钥验证
        print("\n4. 使用公钥验证签名...")
        is_valid = self.verify_with_public_key(nickname, nonce, signature)
        print(f"签名验证结果: {'有效' if is_valid else '无效'}")

        # 5. 演示签名被篡改的情况
        print("\n5. 演示篡改签名的情况...")
        if signature:
            # 修改一个字符
            tampered_signature = signature[:-2] + ("00" if signature[-2:] != "00" else "FF")
            is_valid_tampered = self.verify_with_public_key(nickname, nonce, tampered_signature)
            print(f"篡改后验证结果: {'有效' if is_valid_tampered else '无效'}")

        return {
            'nickname': nickname,
            'nonce': nonce,
            'message_hash': message_hash,
            'signature': signature,
            'public_key': keys['public_key'],
            'private_key': keys['private_key']
        }


# 运行演示
if __name__ == "__main__":
    # 安装所需库（如果尚未安装）:
    # pip install pycryptodome

    try:
        # 创建系统实例
        rsa_system = RSASignatureSystem(key_size=1024)  # 使用1024位密钥加速演示

        # 运行完整演示
        result = rsa_system.demo_workflow("Lito666")

        print("\n" + "=" * 60)
        print("演示总结：")
        print("=" * 60)
        print(f"昵称: {result['nickname']}")
        print(f"Nonce: {result['nonce']}")
        print(f"消息哈希: {result['message_hash']}")
        print(f"签名长度: {len(result['signature'])} 字符")

    except ImportError as e:
        print("错误：缺少必要的库")
        print("请安装: pip install pycryptodome")
    except Exception as e:
        print(f"运行时错误: {e}")
