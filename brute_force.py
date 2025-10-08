import threading
import time
from queue import Queue
from S_DES import SDES


class BruteForce:
    """S-DES 暴力破解（返回10位二进制密钥）"""

    def __init__(self, plaintext, ciphertext):
        """
        初始化暴力破解
        :param plaintext: 已知明文（8-bit 二进制字符串）
        :param ciphertext: 对应密文（8-bit 二进制字符串）
        """
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.found_keys = []  # 存储10位二进制密钥字符串
        self.progress = 0
        self.total = 1024  # 2^10 种可能的密钥
        self.start_time = None
        self.end_time = None

    @staticmethod
    def int_to_10bit_key(key_int):
        """
        将整数密钥转换为10位二进制字符串
        :param key_int: 0-1023之间的整数
        :return: 10位二进制字符串（补前导零）
        """
        return f"{key_int:010b}"

    def crack_single_thread(self, start_key=0, end_key=1024):
        """
        单线程暴力破解
        :param start_key: 起始密钥（整数）
        :param end_key: 结束密钥（整数）
        :return: 找到的10位二进制密钥列表
        """
        found = []
        for key_int in range(start_key, end_key):
            # 将整数密钥转换为10位二进制字符串
            key_str = self.int_to_10bit_key(key_int)

            # 使用二进制密钥进行加密
            sdes = SDES(key_str)
            encrypted = sdes.encrypt_block(self.plaintext)

            # 比较加密结果与目标密文
            if encrypted == self.ciphertext:
                found.append(key_str)  # 存储二进制密钥

            self.progress += 1

        return found

    def crack_multi_thread(self, num_threads=4):
        """
        多线程暴力破解
        :param num_threads: 线程数
        :return: 找到的10位二进制密钥列表
        """
        self.start_time = time.time()
        self.progress = 0
        self.found_keys = []

        # 分配任务
        chunk_size = self.total // num_threads
        threads = []
        results = Queue()

        def worker(start, end):
            found = self.crack_single_thread(start, end)
            results.put(found)

        # 启动线程
        for i in range(num_threads):
            start = i * chunk_size
            # 最后一个线程处理剩余的所有密钥
            end = start + chunk_size if i < num_threads - 1 else self.total
            thread = threading.Thread(target=worker, args=(start, end))
            thread.start()
            threads.append(thread)

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 收集结果
        while not results.empty():
            self.found_keys.extend(results.get())

        self.end_time = time.time()
        return self.found_keys

    def get_elapsed_time(self):
        """获取破解耗时"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0
