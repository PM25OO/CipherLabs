import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib


class DES:
    """纯 Python DES 实现（ECB + PKCS#7）。"""

    # 初始置换表
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
    ]

    # 逆初始置换表
    FP = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
    ]

    # 扩展置换表
    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1,
    ]

    # P 置换表
    P = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25,
    ]

    # PC-1
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4,
    ]

    # PC-2
    PC2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32,
    ]

    # 左移位数
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # S 盒
    SBOX = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ],
    ]

    @staticmethod
    def _bytes_to_bits(data: bytes) -> list[int]:
        bits: list[int] = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def _bits_to_bytes(bits: list[int]) -> bytes:
        data = bytearray()
        for i in range(0, len(bits), 8):
            value = 0
            for bit in bits[i:i + 8]:
                value = (value << 1) | bit
            data.append(value)
        return bytes(data)

    @staticmethod
    def _permute(bits: list[int], table: list[int]) -> list[int]:
        return [bits[index - 1] for index in table]

    @staticmethod
    def _xor(left: list[int], right: list[int]) -> list[int]:
        return [a ^ b for a, b in zip(left, right)]

    @staticmethod
    def _left_rotate(bits: list[int], n: int) -> list[int]:
        return bits[n:] + bits[:n]

    def _generate_round_keys(self, key: bytes) -> list[list[int]]:
        key_bits = self._bytes_to_bits(key)
        key_bits = self._permute(key_bits, self.PC1)
        left = key_bits[:28]
        right = key_bits[28:]
        round_keys = []
        for shift in self.SHIFTS:
            left = self._left_rotate(left, shift)
            right = self._left_rotate(right, shift)
            round_key = self._permute(left + right, self.PC2)
            round_keys.append(round_key)
        return round_keys

    def _sbox_substitute(self, bits48: list[int]) -> list[int]:
        result: list[int] = []
        for box_index in range(8):
            chunk = bits48[box_index * 6:(box_index + 1) * 6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            value = self.SBOX[box_index][row][col]
            for i in range(3, -1, -1):
                result.append((value >> i) & 1)
        return result

    def _feistel(self, right32: list[int], round_key: list[int]) -> list[int]:
        expanded = self._permute(right32, self.E)
        mixed = self._xor(expanded, round_key)
        substituted = self._sbox_substitute(mixed)
        return self._permute(substituted, self.P)

    def _crypt_block(self, block8: bytes, round_keys: list[list[int]]) -> bytes:
        bits = self._bytes_to_bits(block8)
        bits = self._permute(bits, self.IP)
        left = bits[:32]
        right = bits[32:]

        for round_key in round_keys:
            new_left = right
            new_right = self._xor(left, self._feistel(right, round_key))
            left, right = new_left, new_right

        combined = right + left  # 交换左右
        combined = self._permute(combined, self.FP)
        return self._bits_to_bytes(combined)

    @staticmethod
    def _pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        if pad_len == 0:
            pad_len = block_size
        return data + bytes([pad_len]) * pad_len

    @staticmethod
    def _pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
        if not data or len(data) % block_size != 0:
            raise ValueError("密文长度不正确，无法去填充")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("填充字节无效")
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("填充内容无效")
        return data[:-pad_len]

    @staticmethod
    def normalize_key(key_text: str) -> bytes:
        """使用 SHA-256 哈希将任意长度的密钥派生为 8 字节的 DES 密钥。
        这比直接截断或补零更安全，避免信息损失和容易被攻击的模式。"""
        key_bytes = key_text.encode("utf-8")
        # 计算 SHA-256 哈希，然后取前 8 字节
        hash_obj = hashlib.sha256(key_bytes)
        return hash_obj.digest()[:8]

    def encrypt(self, plaintext: str, key_text: str) -> str:
        key = self.normalize_key(key_text)
        round_keys = self._generate_round_keys(key)
        data = plaintext.encode("utf-8")
        padded = self._pkcs7_pad(data)
        encrypted = bytearray()
        for index in range(0, len(padded), 8):
            encrypted.extend(self._crypt_block(padded[index:index + 8], round_keys))
        return encrypted.hex().upper()

    def decrypt(self, ciphertext_hex: str, key_text: str) -> str:
        key = self.normalize_key(key_text)
        round_keys = self._generate_round_keys(key)
        cipher_bytes = bytes.fromhex("".join(ciphertext_hex.split()))
        if len(cipher_bytes) % 8 != 0:
            raise ValueError("密文必须是 8 字节对齐的十六进制数据")

        decrypted = bytearray()
        for index in range(0, len(cipher_bytes), 8):
            decrypted.extend(self._crypt_block(cipher_bytes[index:index + 8], list(reversed(round_keys))))
        unpadded = self._pkcs7_unpad(bytes(decrypted))
        return unpadded.decode("utf-8")


class DESApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("DES 加解密工具")
        self.root.geometry("880x700")
        self.root.minsize(820, 640)
        self.root.configure(bg="#f5f7fb")

        self.des = DES()

        title_font = ("Microsoft YaHei", 16, "bold")
        label_font = ("Microsoft YaHei", 10, "bold")
        text_font = ("Consolas", 11)

        header = tk.Frame(root, bg="#f5f7fb")
        header.pack(fill=tk.X, padx=20, pady=(18, 8))
        tk.Label(header, text="DES 加解密程序", font=title_font, bg="#f5f7fb", fg="#1f2d3d").pack(anchor="w")
        tk.Label(
            header,
            text="",
            font=("Microsoft YaHei", 9),
            bg="#f5f7fb",
            fg="#5c677d",
        ).pack(anchor="w", pady=(4, 0))

        form = tk.Frame(root, bg="#f5f7fb")
        form.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # 密钥
        key_frame = tk.Frame(form, bg="#f5f7fb")
        key_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(key_frame, text="密钥", font=label_font, bg="#f5f7fb").pack(anchor="w")
        self.key_entry = tk.Entry(key_frame, font=text_font, relief=tk.GROOVE, bd=2)
        self.key_entry.insert(0, "crypto")
        self.key_entry.pack(fill=tk.X, pady=(6, 0))
        # 绑定密钥输入事件，实时更新处理后的密钥显示
        self.key_entry.bind("<KeyRelease>", lambda e: self.update_derived_key_display())
        
        # 处理后的密钥显示
        tk.Label(key_frame, text="处理后的密钥", font=("Microsoft YaHei", 9), bg="#f5f7fb", fg="#666666").pack(anchor="w", pady=(10, 4))
        self.derived_key_display = tk.Text(key_frame, height=2, font=("Consolas", 9), relief=tk.SUNKEN, bd=1, bg="#eeeeee", state=tk.DISABLED)
        self.derived_key_display.pack(fill=tk.X, pady=(0, 0))
        # 初始化显示
        self.update_derived_key_display()

        # 明文与密文左右布局
        panes = tk.Frame(form, bg="#f5f7fb")
        panes.pack(fill=tk.BOTH, expand=True)

        left_panel = tk.LabelFrame(panes, text="明文框", font=label_font, bg="#f5f7fb", padx=10, pady=10)
        right_panel = tk.LabelFrame(panes, text="密文框", font=label_font, bg="#f5f7fb", padx=10, pady=10)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))

        self.plain_text = scrolledtext.ScrolledText(left_panel, font=text_font, height=12, wrap=tk.WORD)
        self.plain_text.pack(fill=tk.BOTH, expand=True)

        self.cipher_text = scrolledtext.ScrolledText(right_panel, font=text_font, height=12, wrap=tk.WORD)
        self.cipher_text.pack(fill=tk.BOTH, expand=True)

        # 操作区
        btn_frame = tk.LabelFrame(
            form,
            text="操作区",
            font=label_font,
            bg="#f5f7fb",
            padx=10,
            pady=12,
        )
        btn_frame.pack(fill=tk.X, pady=(14, 0))

        tk.Button(
            btn_frame,
            text="加密",
            command=self.handle_encrypt,
            width=16,
            font=("Microsoft YaHei", 10, "bold"),
            bg="#2f80ed",
            fg="white",
            activebackground="#2366c7",
            relief=tk.FLAT,
            padx=10,
            pady=6,
        ).pack(side=tk.LEFT, padx=(0, 12))
        tk.Button(
            btn_frame,
            text="解密",
            command=self.handle_decrypt,
            width=16,
            font=("Microsoft YaHei", 10, "bold"),
            bg="#27ae60",
            fg="white",
            activebackground="#1f8a4d",
            relief=tk.FLAT,
            padx=10,
            pady=6,
        ).pack(side=tk.LEFT, padx=(0, 12))
        tk.Button(
            btn_frame,
            text="清空",
            command=self.handle_clear,
            width=16,
            font=("Microsoft YaHei", 10, "bold"),
            bg="#eb5757",
            fg="white",
            activebackground="#c84242",
            relief=tk.FLAT,
            padx=10,
            pady=6,
        ).pack(side=tk.LEFT)

        # 解密文输出
        decrypt_frame = tk.LabelFrame(form, text="解密文框", font=label_font, bg="#f5f7fb", padx=10, pady=10)
        decrypt_frame.pack(fill=tk.BOTH, expand=True, pady=(14, 0))
        self.decrypt_text = scrolledtext.ScrolledText(decrypt_frame, font=text_font, height=8, wrap=tk.WORD)
        self.decrypt_text.pack(fill=tk.BOTH, expand=True)

    @staticmethod
    def _get_text(widget: tk.Text) -> str:
        return widget.get("1.0", tk.END).strip()

    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, value)

    def handle_encrypt(self) -> None:
        self.update_derived_key_display()
        plaintext = self._get_text(self.plain_text)
        key = self.key_entry.get().strip()
        if not plaintext:
            messagebox.showwarning("提示", "请输入明文。")
            return
        if not key:
            messagebox.showwarning("提示", "请输入密钥。")
            return

        try:
            ciphertext = self.des.encrypt(plaintext, key)
            self._set_text(self.cipher_text, ciphertext)
            self._set_text(self.decrypt_text, "")
        except Exception as exc:
            messagebox.showerror("加密失败", str(exc))

    def handle_decrypt(self) -> None:
        self.update_derived_key_display()
        ciphertext = self._get_text(self.cipher_text)
        key = self.key_entry.get().strip()
        if not ciphertext:
            messagebox.showwarning("提示", "请输入密文。")
            return
        if not key:
            messagebox.showwarning("提示", "请输入密钥。")
            return

        try:
            plaintext = self.des.decrypt(ciphertext, key)
            self._set_text(self.decrypt_text, plaintext)
        except ValueError as exc:
            messagebox.showerror("解密失败", f"{exc}")
        except UnicodeDecodeError:
            messagebox.showerror("解密失败", "解密结果不是有效的 UTF-8 文本，请检查密文或密钥是否正确。")
        except Exception as exc:
            messagebox.showerror("解密失败", f"{exc}")

    def update_derived_key_display(self) -> None:
        """实时更新处理后密钥的显示"""
        key_text = self.key_entry.get().strip()
        if not key_text:
            key_text = "(空)"
        try:
            derived_key = self.des.normalize_key(key_text)
            hex_display = derived_key.hex().upper()
            # 每 16 个字符换行，方便阅读
            formatted_hex = "\n".join([hex_display[i:i+16] for i in range(0, len(hex_display), 16)])
        except Exception:
            formatted_hex = "(处理失败)"
        
        self.derived_key_display.config(state=tk.NORMAL)
        self.derived_key_display.delete("1.0", tk.END)
        self.derived_key_display.insert(tk.END, formatted_hex)
        self.derived_key_display.config(state=tk.DISABLED)

    def handle_clear(self) -> None:
        self._set_text(self.plain_text, "")
        self._set_text(self.cipher_text, "")
        self._set_text(self.decrypt_text, "")
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, "crypto")
        self.update_derived_key_display()


if __name__ == "__main__":
    root = tk.Tk()
    app = DESApp(root)
    root.mainloop()
