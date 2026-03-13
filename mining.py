'''
https://decert.me/challenge/45779e03-7905-469e-822e-3ec3746d9ece
实践 POW， 编写程序（编程语言不限）用自己的昵称 + nonce，不断修改nonce 进行 sha256 Hash 运算：

直到满足 4 个 0 开头的哈希值，打印出花费的时间、Hash 的内容及Hash值。
再次运算直到满足 5 个 0 开头的哈希值，打印出花费的时间、Hash 的内容及Hash值。
'''



import hashlib
import time
from datetime import datetime, timedelta


def pow_calculator(nickname, target_zeros, max_attempts=None):
    """
    计算POW，找到以指定数量0开头的哈希值

    Args:
        nickname: 你的昵称
        target_zeros: 目标零的数量（4或5）
        max_attempts: 最大尝试次数（可选，用于安全限制）
    """

    print(f"开始计算POW: 昵称='{nickname}', 目标={target_zeros}个0开头")
    start_time = time.time()
    nonce = 0
    attempts = 0

    # 目标前缀：比如4个0就是"0000"，5个0就是"00000"
    target_prefix = "0" * target_zeros

    while True:
        # 构建要哈希的字符串
        data = f"{nickname}{nonce}"

        # 计算SHA256哈希
        hash_result = hashlib.sha256(data.encode()).hexdigest()

        attempts += 1

        # 检查是否满足条件
        if hash_result.startswith(target_prefix):
            end_time = time.time()
            elapsed = end_time - start_time
            return {
                'nonce': nonce,
                'hash': hash_result,
                'attempts': attempts,
                'time': elapsed,
                'data': data
            }

        nonce += 1

        # 安全限制：防止无限循环
        if max_attempts and attempts >= max_attempts:
            print(f"⚠️  达到最大尝试次数 {max_attempts:,}，未找到符合条件的哈希值")
            return None


def main():
    # 配置参数
    nickname = "Lito666"  # 你可以改成你的昵称
    max_attempts_4zeros = 10000000  # 4个0的最大尝试次数
    max_attempts_5zeros = 50000000  # 5个0的最大尝试次数

    print(f"使用昵称: {nickname}")
    print("-" * 60)

    try:
        # 第一阶段：找到4个0开头的哈希值
        result_4zeros = pow_calculator(nickname, 4, max_attempts_4zeros)

        if result_4zeros:

            # 第二阶段：找到5个0开头的哈希值
            result_5zeros = pow_calculator(nickname, 5, max_attempts_5zeros)

            if result_4zeros and result_5zeros:
                print("结果对比:")
                print(f"{'=' * 60}")
                print(f"4个0开头:")
                print(f"  尝试次数: {result_4zeros['attempts']:,} 次")
                print(f"  耗时: {result_4zeros['time']:.4f} 秒")
                print(f"  Nonce: {result_4zeros['nonce']}")
