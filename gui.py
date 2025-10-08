from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QGroupBox, QProgressBar,
                             QMessageBox, QRadioButton, QFrame, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon
from brute_force import BruteForce  # 确保该文件存在
from S_DES import SDES  # 导入SDES类


class BruteForceThread(QThread):
    """暴力破解线程"""
    finished = pyqtSignal(list, float)

    def __init__(self, plaintext, ciphertext, num_threads=4):  # 默认4线程
        super().__init__()
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.num_threads = num_threads

    def run(self):
        brute_force = BruteForce(self.plaintext, self.ciphertext)
        keys = brute_force.crack_multi_thread(self.num_threads)
        elapsed = brute_force.get_elapsed_time()
        self.finished.emit(keys, elapsed)


class SDESSimpleGui(QMainWindow):
    """横向布局的S-DES GUI，所有功能在同一界面"""

    def __init__(self):
        super().__init__()
        # 设置全局字体
        font = QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(10)
        self.setFont(font)

        self.init_ui()

    def init_ui(self):
        """初始化界面"""
        self.setWindowTitle('S-DES 加密解密系统')
        self.setGeometry(100, 100, 1200, 600)

        # 设置窗口样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
            }
            .Module {
                background-color: white;
                border-radius: 8px;
                padding: 15px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            QLabel#SectionTitle {
                color: #2c3e50;
                font-size: 14px;
                font-weight: bold;
                margin-bottom: 10px;
                padding-bottom: 5px;
                border-bottom: 1px solid #eee;
            }
            QLabel {
                color: #343a40;
                margin: 8px 0 5px 0;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 6px 15px;
                border-radius: 4px;
                font-weight: 500;
                margin-top: 10px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #2471a3;
            }
            QLineEdit, QTextEdit {
                border: 1px solid #ced4da;
                border-radius: 4px;
                padding: 6px;
                background-color: white;
            }
            QLineEdit:focus, QTextEdit:focus {
                border-color: #3498db;
                border-width: 1.5px;
                outline: none;
            }
            QTextEdit[readOnly="true"] {
                background-color: #f8f9fa;
                color: #343a40;
            }
            QProgressBar {
                border: 1px solid #ced4da;
                border-radius: 4px;
                text-align: center;
                height: 18px;
                margin-top: 10px;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 2px;
            }
            QRadioButton {
                color: #343a40;
                margin-right: 15px;
                padding: 3px;
            }
            QSplitter::handle {
                background-color: #e9ecef;
                width: 8px;
                height: 8px;
            }
        """)

        # 中心部件与主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # 标题
        title_label = QLabel("S-DES 加密解密系统")
        title_font = QFont()
        title_font.setFamily("Microsoft YaHei")
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #2c3e50;")
        main_layout.addWidget(title_label)

        # 横向分割的主要功能区
        main_splitter = QSplitter(Qt.Horizontal)

        # 左侧：加密解密模块
        encrypt_decrypt_module = self.create_encrypt_decrypt_module()
        main_splitter.addWidget(encrypt_decrypt_module)

        # 右侧：暴力破解模块
        brute_force_module = self.create_brute_force_module()
        main_splitter.addWidget(brute_force_module)

        # 设置初始大小比例
        main_splitter.setSizes([550, 550])

        main_layout.addWidget(main_splitter)

    def create_encrypt_decrypt_module(self):
        """创建加密解密模块（左侧）"""
        widget = QFrame()
        widget.setObjectName("Module")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # 模块标题
        title = QLabel("加密解密操作")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        # 1. 配置区域
        config_frame = QFrame()
        config_layout = QVBoxLayout(config_frame)

        # 模式选择
        mode_label = QLabel("工作模式：")
        mode_layout = QHBoxLayout()
        self.binary_mode_radio = QRadioButton("二进制模式")
        self.ascii_mode_radio = QRadioButton("ASCII模式")
        self.binary_mode_radio.setChecked(True)
        mode_layout.addWidget(self.binary_mode_radio)
        mode_layout.addWidget(self.ascii_mode_radio)
        mode_layout.addStretch()

        # 密钥设置
        key_layout = QHBoxLayout()
        key_label = QLabel("10位二进制密钥：")
        key_label.setFixedWidth(100)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText('例如：1010000010')
        self.key_input.setMaxLength(10)
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_input)

        config_layout.addWidget(mode_label)
        config_layout.addLayout(mode_layout)
        config_layout.addLayout(key_layout)
        layout.addWidget(config_frame)

        # 2. 加密区域
        encrypt_frame = QFrame()
        encrypt_layout = QVBoxLayout(encrypt_frame)

        encrypt_label = QLabel("加密操作")
        encrypt_label.setStyleSheet("font-weight: 500; color: #495057;")

        # 明文输入
        self.plaintext_input = QTextEdit()
        self.plaintext_input.setPlaceholderText('二进制模式：8位二进制数，可多个用空格分隔')
        self.plaintext_input.setMaximumHeight(80)
        # 切换模式时改变输入提示
        self.binary_mode_radio.toggled.connect(lambda: self.update_placeholders())

        # 加密按钮
        encrypt_btn = QPushButton('执行加密')
        encrypt_btn.setIcon(QIcon.fromTheme("document-encrypt", QIcon()))
        encrypt_btn.clicked.connect(self.encrypt)

        # 密文输出
        cipher_label = QLabel("加密结果：")
        self.ciphertext_output = QTextEdit()
        self.ciphertext_output.setReadOnly(True)
        self.ciphertext_output.setMaximumHeight(80)

        encrypt_layout.addWidget(encrypt_label)
        encrypt_layout.addWidget(self.plaintext_input)
        encrypt_layout.addWidget(encrypt_btn, alignment=Qt.AlignRight)
        encrypt_layout.addWidget(cipher_label)
        encrypt_layout.addWidget(self.ciphertext_output)
        layout.addWidget(encrypt_frame)

        # 3. 解密区域
        decrypt_frame = QFrame()
        decrypt_layout = QVBoxLayout(decrypt_frame)

        decrypt_label = QLabel("解密操作")
        decrypt_label.setStyleSheet("font-weight: 500; color: #495057;")

        # 密文输入
        self.ciphertext_input = QTextEdit()
        self.ciphertext_input.setPlaceholderText('二进制模式：8位二进制数，可多个用空格分隔')
        self.ciphertext_input.setMaximumHeight(80)

        # 解密按钮
        decrypt_btn = QPushButton('执行解密')
        decrypt_btn.setIcon(QIcon.fromTheme("document-decrypt", QIcon()))
        decrypt_btn.clicked.connect(self.decrypt)

        # 明文输出
        plain_label = QLabel("解密结果：")
        self.plaintext_output = QTextEdit()
        self.plaintext_output.setReadOnly(True)
        self.plaintext_output.setMaximumHeight(80)

        decrypt_layout.addWidget(decrypt_label)
        decrypt_layout.addWidget(self.ciphertext_input)
        decrypt_layout.addWidget(decrypt_btn, alignment=Qt.AlignRight)
        decrypt_layout.addWidget(plain_label)
        decrypt_layout.addWidget(self.plaintext_output)
        layout.addWidget(decrypt_frame)

        layout.addStretch()
        return widget

    def create_brute_force_module(self):
        """创建暴力破解模块（右侧）"""
        widget = QFrame()
        widget.setObjectName("Module")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # 模块标题
        title = QLabel("密钥暴力破解")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        # 1. 破解参数
        params_frame = QFrame()
        params_layout = QVBoxLayout(params_frame)

        # 明文输入
        self.bf_plaintext_input = QLineEdit()
        self.bf_plaintext_input.setPlaceholderText('8位二进制明文')
        self.bf_plaintext_input.setMaxLength(8)

        # 密文输入
        self.bf_ciphertext_input = QLineEdit()
        self.bf_ciphertext_input.setPlaceholderText('对应的8位二进制密文')
        self.bf_ciphertext_input.setMaxLength(8)

        # 线程提示
        note_label = QLabel("系统将使用4线程进行暴力破解")
        note_label.setStyleSheet("color: #6c757d; font-style: italic; font-size: 9pt;")

        params_layout.addWidget(QLabel("已知明文："))
        params_layout.addWidget(self.bf_plaintext_input)
        params_layout.addWidget(QLabel("对应密文："))
        params_layout.addWidget(self.bf_ciphertext_input)
        params_layout.addWidget(note_label)
        layout.addWidget(params_frame)

        # 2. 破解控制
        control_frame = QFrame()
        control_layout = QVBoxLayout(control_frame)

        self.bf_start_btn = QPushButton('开始暴力破解')
        self.bf_start_btn.setIcon(QIcon.fromTheme("system-search", QIcon()))
        self.bf_start_btn.clicked.connect(self.start_brute_force)

        self.bf_progress = QProgressBar()
        self.bf_progress.setRange(0, 0)
        self.bf_progress.hide()

        control_layout.addWidget(self.bf_start_btn, alignment=Qt.AlignRight)
        control_layout.addWidget(self.bf_progress)
        layout.addWidget(control_frame)

        # 3. 破解结果
        result_frame = QFrame()
        result_layout = QVBoxLayout(result_frame)

        result_label = QLabel("破解结果：")
        self.bf_result_output = QTextEdit()
        self.bf_result_output.setReadOnly(True)

        result_layout.addWidget(result_label)
        result_layout.addWidget(self.bf_result_output)
        layout.addWidget(result_frame)

        layout.addStretch()
        return widget

    # ---------------------- 辅助方法 ----------------------
    def update_placeholders(self):
        """根据选择的模式更新输入框提示文字"""
        if self.binary_mode_radio.isChecked():
            self.plaintext_input.setPlaceholderText('8位二进制数，可多个用空格分隔（例如：10101010 01010101）')
            self.ciphertext_input.setPlaceholderText('8位二进制数，可多个用空格分隔（例如：11001010 00110110）')
        else:
            self.plaintext_input.setPlaceholderText('ASCII字符串（例如：Hello World!）')
            self.ciphertext_input.setPlaceholderText('加密后的ASCII字符串')

    def validate_key(self, key_str):
        """验证密钥：10位二进制"""
        if len(key_str) != 10:
            QMessageBox.warning(self, '输入错误', '密钥必须是10位二进制数！')
            return False
        if not all(c in '01' for c in key_str):
            QMessageBox.warning(self, '输入错误', '密钥只能包含数字0和1！')
            return False
        return True

    def validate_binary_input(self, input_str, desc):
        """验证二进制输入"""
        blocks = input_str.split()
        for block in blocks:
            if len(block) != 8:
                QMessageBox.warning(self, '输入错误', f'{desc}必须是8位二进制数！')
                return False
            if not all(c in '01' for c in block):
                QMessageBox.warning(self, '输入错误', f'{desc}只能包含数字0和1！')
                return False
        return True

    # ---------------------- 核心功能逻辑 ----------------------
    def encrypt(self):
        """执行加密（根据模式选择相应方法）"""
        key = self.key_input.text().strip()
        if not self.validate_key(key):
            return

        plaintext = self.plaintext_input.toPlainText().strip()
        if not plaintext:
            QMessageBox.warning(self, '输入错误', '请输入明文！')
            return

        try:
            sdes = SDES(key)
            result = ""

            if self.binary_mode_radio.isChecked():
                # 二进制模式加密
                if not self.validate_binary_input(plaintext, '明文'):
                    return

                # 处理多个块
                blocks = plaintext.split()
                encrypted_blocks = []
                for block in blocks:
                    encrypted = sdes.encrypt_block(block)
                    encrypted_blocks.append(encrypted)
                result = ' '.join(encrypted_blocks)

            else:
                # ASCII模式加密
                result = sdes.encrypt_ascii(plaintext)

            self.ciphertext_output.setText(result)
            QMessageBox.information(self, '加密成功', '加密完成！')

        except Exception as e:
            QMessageBox.critical(self, '加密失败', f'错误原因：{str(e)}')

    def decrypt(self):
        """执行解密（根据模式选择相应方法）"""
        key = self.key_input.text().strip()
        if not self.validate_key(key):
            return

        ciphertext = self.ciphertext_input.toPlainText().strip()
        if not ciphertext:
            QMessageBox.warning(self, '输入错误', '请输入密文！')
            return

        try:
            sdes = SDES(key)
            result = ""

            if self.binary_mode_radio.isChecked():
                # 二进制模式解密
                if not self.validate_binary_input(ciphertext, '密文'):
                    return

                # 处理多个块
                blocks = ciphertext.split()
                decrypted_blocks = []
                for block in blocks:
                    decrypted = sdes.decrypt_block(block)
                    decrypted_blocks.append(decrypted)
                result = ' '.join(decrypted_blocks)

            else:
                # ASCII模式解密
                result = sdes.decrypt_ascii(ciphertext)

            self.plaintext_output.setText(result)
            QMessageBox.information(self, '解密成功', '解密完成！')

        except Exception as e:
            QMessageBox.critical(self, '解密失败', f'错误原因：{str(e)}')

    def start_brute_force(self):
        """启动暴力破解（使用默认4线程）"""
        plaintext = self.bf_plaintext_input.text().strip()
        ciphertext = self.bf_ciphertext_input.text().strip()

        # 验证输入
        if not self.validate_binary_input(plaintext, '明文'):
            return
        if not self.validate_binary_input(ciphertext, '密文'):
            return

        # 初始化破解状态
        self.bf_start_btn.setEnabled(False)
        self.bf_progress.show()
        self.bf_result_output.clear()

        # 启动破解线程，使用默认4线程
        self.brute_thread = BruteForceThread(plaintext, ciphertext)
        self.brute_thread.finished.connect(self.on_brute_force_finished)
        self.brute_thread.start()

    def on_brute_force_finished(self, keys, elapsed):
        """暴力破解完成回调"""
        self.bf_start_btn.setEnabled(True)
        self.bf_progress.hide()

        if not keys:
            result = f'破解失败：未找到匹配的10位密钥\n耗时：{elapsed:.2f}秒'
        else:
            result = f'破解成功！\n找到 {len(keys)} 个匹配密钥：\n'
            for i, key in enumerate(keys, 1):
                result += f'  {i}. 密钥：{key}\n'
            result += f'\n总耗时：{elapsed:.2f}秒'

        self.bf_result_output.setText(result)
        QMessageBox.information(self, '破解完成', result.split('\n')[0])
