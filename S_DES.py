class SDES:
    """S-DES 加密解密算法实现"""

    # 置换盒定义
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    P4 = [2, 4, 3, 1]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]

    # S盒定义（注意：S2已修改）
    S1 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ]

    S2 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]

    def __init__(self, key=None):
        """
        初始化 S-DES
        :param key: 10-bit 密钥（字符串或整数）
        """
        self.key = key
        self.k1 = None
        self.k2 = None
        if key is not None:
            self.generate_keys(key)

    @staticmethod
    def permute(input_bits, permutation_table):
        """
        根据置换表进行置换
        :param input_bits: 输入比特串（列表）
        :param permutation_table: 置换表
        :return: 置换后的比特串
        """
        return [input_bits[i - 1] for i in permutation_table]

    @staticmethod
    def left_shift(bits, n):
        """
        循环左移
        :param bits: 比特串
        :param n: 左移位数
        :return: 左移后的比特串
        """
        return bits[n:] + bits[:n]

    @staticmethod
    def xor(bits1, bits2):
        """
        异或运算
        :param bits1: 比特串1
        :param bits2: 比特串2
        :return: 异或结果
        """
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def s_box(self, bits, s_box_table):
        """
        S盒替换
        :param bits: 4-bit 输入
        :param s_box_table: S盒表
        :return: 2-bit 输出
        """
        row = (bits[0] << 1) + bits[3]
        col = (bits[1] << 1) + bits[2]
        value = s_box_table[row][col]
        return [(value >> 1) & 1, value & 1]

    def f_function(self, right_bits, subkey):
        """
        轮函数 F
        :param right_bits: 右半部分 4-bit
        :param subkey: 子密钥 8-bit
        :return: 4-bit 输出
        """
        # 扩展置换 E/P
        expanded = self.permute(right_bits, self.EP)

        # 与子密钥异或
        xored = self.xor(expanded, subkey)

        # S盒替换
        left = self.s_box(xored[:4], self.S1)
        right = self.s_box(xored[4:], self.S2)

        # P4 置换
        combined = left + right
        return self.permute(combined, self.P4)

    def generate_keys(self, key):
        """
        生成子密钥 K1 和 K2
        :param key: 10-bit 主密钥（字符串或整数）
        """
        # 转换为比特列表
        if isinstance(key, str):
            key_bits = [int(b) for b in key]
        else:
            key_bits = [(key >> (9 - i)) & 1 for i in range(10)]

        # P10 置换
        key_p10 = self.permute(key_bits, self.P10)

        # 分成两半
        left = key_p10[:5]
        right = key_p10[5:]

        # 生成 K1：左移1位
        left1 = self.left_shift(left, 1)
        right1 = self.left_shift(right, 1)
        self.k1 = self.permute(left1 + right1, self.P8)

        # 生成 K2：再左移2位（总共左移3位）
        left2 = self.left_shift(left1, 2)
        right2 = self.left_shift(right1, 2)
        self.k2 = self.permute(left2 + right2, self.P8)

    def encrypt_block(self, plaintext):
        """
        加密单个 8-bit 数据块
        :param plaintext: 8-bit 明文（字符串或整数）
        :return: 8-bit 密文（比特列表）
        """
        # 转换为比特列表
        if isinstance(plaintext, str):
            bits = [int(b) for b in plaintext]
        else:
            bits = [(plaintext >> (7 - i)) & 1 for i in range(8)]

        # 初始置换 IP
        bits = self.permute(bits, self.IP)

        # 第一轮
        left = bits[:4]
        right = bits[4:]
        f_result = self.f_function(right, self.k1)
        left = self.xor(left, f_result)

        # 交换
        bits = right + left

        # 第二轮
        left = bits[:4]
        right = bits[4:]
        f_result = self.f_function(right, self.k2)
        left = self.xor(left, f_result)

        # 最终置换 IP^-1
        bits = left + right
        ciphertext = self.permute(bits, self.IP_INV)
        bits2 = "".join(str(bit) for bit in ciphertext)
        return bits2

        #return ciphertext

    def decrypt_block(self, ciphertext):
        """
        解密单个 8-bit 数据块
        :param ciphertext: 8-bit 密文（字符串或整数）
        :return: 8-bit 明文（比特列表）
        """
        # 转换为比特列表
        if isinstance(ciphertext, str):
            bits = [int(b) for b in ciphertext]
        else:
            bits = [(ciphertext >> (7 - i)) & 1 for i in range(8)]

        # 初始置换 IP
        bits = self.permute(bits, self.IP)

        # 第一轮（使用 K2）
        left = bits[:4]
        right = bits[4:]
        f_result = self.f_function(right, self.k2)
        left = self.xor(left, f_result)

        # 交换
        bits = right + left

        # 第二轮（使用 K1）
        left = bits[:4]
        right = bits[4:]
        f_result = self.f_function(right, self.k1)
        left = self.xor(left, f_result)

        # 最终置换 IP^-1
        bits = left + right
        plaintext = self.permute(bits, self.IP_INV)#这里return回一个列表
        bits2 = "".join(str(bit) for bit in plaintext)
        return bits2
        #return plaintext

    def encrypt_ascii(self, text: str) -> str:
        result = ""
        # 1. 将文本转换为UTF-8编码的字节序列（处理多语言字符）
        utf8_bytes = text.encode('utf-8')

        for byte_val in utf8_bytes:
            # 2. 将每个字节转为8位二进制字符串（如 65 → "01000001"）
            binary = format(byte_val, '08b')
            # 3. 调用加密核心方法处理二进制字符串（需要key参与）
            encrypted = self.encrypt_block(binary)
            # 4. 将加密后的二进制转回整数，再转为对应ASCII字符
            encrypted_ascii_val = int(encrypted, 2)
            result += chr(encrypted_ascii_val)

        return result

    def decrypt_ascii(self, text: str) -> str:
        result_bytes = []

        for char in text:
            # 1. 将加密后的字符转为ASCII码值，再转为8位二进制
            ascii_val = ord(char)
            binary = format(ascii_val, '08b')
            # 2. 调用解密核心方法处理二进制字符串（使用相同key）
            decrypted = self.decrypt_block(binary)
            # 3. 将解密后的二进制转回字节值
            byte_val = int(decrypted, 2)
            result_bytes.append(byte_val)

        # 4. 将字节列表组合成字节序列，再解码为UTF-8字符串
        return bytes(result_bytes).decode('utf-8')



    def encrypt(self, plaintext, output_format='ascii'):
        """
        加密（支持字符串输入）
        :param plaintext: 明文（8-bit 二进制字符串或 ASCII 字符串）
        :param output_format: 输出格式 'binary' 或 'ascii'
        :return: 密文
        """
        if len(plaintext) == 8 and all(c in '01' for c in plaintext):
            # 单个 8-bit 块
            result = self.encrypt_block(plaintext)
            return ''.join(map(str, result))
        else:
            # ASCII 字符串
            result = []
            for char in plaintext:
                byte_val = ord(char)
                encrypted = self.encrypt_block(byte_val)
                if output_format == 'binary':
                    result.append(''.join(map(str, encrypted)))
                else:
                    # 转换为整数
                    encrypted_val = sum(bit << (7 - i) for i, bit in enumerate(encrypted))
                    result.append(chr(encrypted_val))

            return ' '.join(result) if output_format == 'binary' else ''.join(result)

    def decrypt(self, ciphertext, input_format='ascii'):
        """
        解密（支持字符串输入）
        :param ciphertext: 密文
        :param input_format: 输入格式 'binary' 或 'ascii'
        :return: 明文
        """
        if input_format == 'binary':
            blocks = ciphertext.split()
            if len(blocks) == 0 and len(ciphertext) == 8:
                blocks = [ciphertext]

            result = []
            for block in blocks:
                decrypted = self.decrypt_block(block)
                decrypted_val = sum(bit << (7 - i) for i, bit in enumerate(decrypted))
                result.append(chr(decrypted_val))

            return ''.join(result)
        else:
            # ASCII 输入
            result = []
            for char in ciphertext:
                byte_val = ord(char)
                decrypted = self.decrypt_block(byte_val)
                decrypted_val = sum(bit << (7 - i) for i, bit in enumerate(decrypted))
                result.append(chr(decrypted_val))

            return ''.join(result)

    @staticmethod
    def bits_to_int(bits):
        """比特列表转整数"""
        return sum(bit << (len(bits) - 1 - i) for i, bit in enumerate(bits))

    @staticmethod
    def int_to_bits(value, length):
        """整数转比特列表"""
        return [(value >> (length - 1 - i)) & 1 for i in range(length)]


# 测试示例
if __name__ == "__main__":
    # 已知测试向量
    key = "1010000010"
    plaintext = "信息安全"

    sdes = SDES(key)
    ciphertext = sdes.encrypt_ascii(plaintext)
    decrypted = sdes.decrypt_ascii(ciphertext)

    print(f"密钥: {key}")
    print(f"明文: {plaintext}")
    print(f"密文: {ciphertext}")
    print(f"解密后: {decrypted}")
    print(f"解密是否正确: {decrypted == plaintext}")
