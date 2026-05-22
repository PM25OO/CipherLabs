import hashlib
import tkinter as tk
from tkinter import messagebox, scrolledtext


SboxTable = [
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]

# System parameter
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

# fixed parameter
CK = [
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
]

ENCRYPT = 0
DECRYPT = 1


class SM4:
	"""SM4 分组密码：ECB + PKCS#7，使用 SHA-256 将任意长度密钥派生为 16 字节。"""

	def _rotl(self, value: int, shift: int) -> int:
		shift %= 32
		return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

	def _tau(self, a: int) -> int:
		b0 = SboxTable[(a >> 24) & 0xFF]
		b1 = SboxTable[(a >> 16) & 0xFF]
		b2 = SboxTable[(a >> 8) & 0xFF]
		b3 = SboxTable[a & 0xFF]
		return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xFFFFFFFF

	def _L(self, b: int) -> int:
		return b ^ self._rotl(b, 2) ^ self._rotl(b, 10) ^ self._rotl(b, 18) ^ self._rotl(b, 24)

	def _L_key(self, b: int) -> int:
		return b ^ self._rotl(b, 13) ^ self._rotl(b, 23)

	def _T(self, x: int) -> int:
		return self._L(self._tau(x))

	def _T_key(self, x: int) -> int:
		return self._L_key(self._tau(x))

	@staticmethod
	def _pad(data: bytes, block_size: int = 16) -> bytes:
		pad_len = block_size - (len(data) % block_size)
		if pad_len == 0:
			pad_len = block_size
		return data + bytes([pad_len]) * pad_len

	@staticmethod
	def _unpad(data: bytes, block_size: int = 16) -> bytes:
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
		"""用 SHA-256 派生 16 字节密钥，适配 SM4 的 128-bit 密钥要求。"""
		return hashlib.sha256(key_text.encode("utf-8")).digest()[:16]

	@staticmethod
	def _bytes_to_words(data: bytes) -> list[int]:
		return [int.from_bytes(data[i:i + 4], "big") for i in range(0, len(data), 4)]

	@staticmethod
	def _words_to_bytes(words: list[int]) -> bytes:
		return b"".join(word.to_bytes(4, "big") for word in words)

	def _key_schedule(self, key: bytes) -> list[int]:
		MK = self._bytes_to_words(key)
		K = [(MK[i] ^ FK[i]) & 0xFFFFFFFF for i in range(4)]
		round_keys = []
		for i in range(32):
			tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]
			rk = (K[i] ^ self._T_key(tmp)) & 0xFFFFFFFF
			round_keys.append(rk)
			K.append(rk)
		return round_keys

	def _crypt_block(self, block: bytes, round_keys: list[int]) -> bytes:
		X = self._bytes_to_words(block)
		for i in range(32):
			tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ round_keys[i]
			X.append((X[i] ^ self._T(tmp)) & 0xFFFFFFFF)
		return self._words_to_bytes([X[35], X[34], X[33], X[32]])

	def encrypt(self, plaintext: str, key_text: str) -> str:
		key = self.normalize_key(key_text)
		round_keys = self._key_schedule(key)
		data = self._pad(plaintext.encode("utf-8"), 16)
		out = bytearray()
		for i in range(0, len(data), 16):
			out.extend(self._crypt_block(data[i:i + 16], round_keys))
		return out.hex().upper()

	def decrypt(self, ciphertext_hex: str, key_text: str) -> str:
		key = self.normalize_key(key_text)
		round_keys = self._key_schedule(key)[::-1]
		cipher_bytes = bytes.fromhex("".join(ciphertext_hex.split()))
		if len(cipher_bytes) % 16 != 0:
			raise ValueError("密文必须是 16 字节对齐的十六进制数据")
		out = bytearray()
		for i in range(0, len(cipher_bytes), 16):
			out.extend(self._crypt_block(cipher_bytes[i:i + 16], round_keys))
		return self._unpad(bytes(out), 16).decode("utf-8")


class SM4App:
	def __init__(self, root: tk.Tk):
		self.root = root
		self.root.title("SM4 加解密工具")
		self.root.geometry("920x760")
		self.root.minsize(860, 680)
		self.root.configure(bg="#f5f7fb")

		self.sm4 = SM4()

		title_font = ("Microsoft YaHei", 16, "bold")
		label_font = ("Microsoft YaHei", 10, "bold")
		text_font = ("Consolas", 11)

		header = tk.Frame(root, bg="#f5f7fb")
		header.pack(fill=tk.X, padx=20, pady=(18, 8))
		tk.Label(header, text="SM4 加解密程序", font=title_font, bg="#f5f7fb", fg="#1f2d3d").pack(anchor="w")

		form = tk.Frame(root, bg="#f5f7fb")
		form.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

		key_frame = tk.Frame(form, bg="#f5f7fb")
		key_frame.pack(fill=tk.X, pady=(0, 10))
		tk.Label(key_frame, text="密钥", font=label_font, bg="#f5f7fb").pack(anchor="w")
		self.key_entry = tk.Entry(key_frame, font=text_font, relief=tk.GROOVE, bd=2)
		self.key_entry.insert(0, "1234567890abcdef")
		self.key_entry.pack(fill=tk.X, pady=(6, 0))
		self.key_entry.bind("<KeyRelease>", lambda _e: self.update_derived_key_display())

		tk.Label(key_frame, text="处理后的密钥（十六进制）", font=("Microsoft YaHei", 9), bg="#f5f7fb", fg="#666666").pack(anchor="w", pady=(10, 4))
		self.derived_key_display = tk.Text(key_frame, height=2, font=("Consolas", 9), relief=tk.SUNKEN, bd=1, bg="#eeeeee", state=tk.DISABLED)
		self.derived_key_display.pack(fill=tk.X)

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

		decrypt_frame = tk.LabelFrame(form, text="解密文框", font=label_font, bg="#f5f7fb", padx=10, pady=10)
		decrypt_frame.pack(fill=tk.BOTH, expand=True, pady=(14, 0))
		self.decrypt_text = scrolledtext.ScrolledText(decrypt_frame, font=text_font, height=8, wrap=tk.WORD)
		self.decrypt_text.pack(fill=tk.BOTH, expand=True)

		btn_frame = tk.LabelFrame(form, text="操作区", font=label_font, bg="#f5f7fb", padx=10, pady=12)
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

		self.update_derived_key_display()

	@staticmethod
	def _get_text(widget: tk.Text) -> str:
		return widget.get("1.0", tk.END).strip()

	@staticmethod
	def _set_text(widget: tk.Text, value: str) -> None:
		widget.delete("1.0", tk.END)
		widget.insert(tk.END, value)

	def update_derived_key_display(self) -> None:
		key_text = self.key_entry.get().strip()
		derived_key = self.sm4.normalize_key(key_text)
		hex_display = derived_key.hex().upper()
		formatted = " ".join(hex_display[i:i + 2] for i in range(0, len(hex_display), 2))
		self.derived_key_display.config(state=tk.NORMAL)
		self.derived_key_display.delete("1.0", tk.END)
		self.derived_key_display.insert(tk.END, formatted)
		self.derived_key_display.config(state=tk.DISABLED)

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
			ciphertext = self.sm4.encrypt(plaintext, key)
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
			plaintext = self.sm4.decrypt(ciphertext, key)
			self._set_text(self.decrypt_text, plaintext)
		except ValueError as exc:
			messagebox.showerror("解密失败", f"{exc}")
		except UnicodeDecodeError:
			messagebox.showerror("解密失败", "解密结果不是有效的 UTF-8 文本，请检查密文或密钥是否正确。")
		except Exception as exc:
			messagebox.showerror("解密失败", f"{exc}")

	def handle_clear(self) -> None:
		self._set_text(self.plain_text, "")
		self._set_text(self.cipher_text, "")
		self._set_text(self.decrypt_text, "")
		self.key_entry.delete(0, tk.END)
		self.key_entry.insert(0, "1234567890abcdef")
		self.update_derived_key_display()


if __name__ == "__main__":
	root = tk.Tk()
	app = SM4App(root)
	root.mainloop()
