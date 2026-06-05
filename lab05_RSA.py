import secrets
import tkinter as tk
from tkinter import messagebox, scrolledtext


SIZE = 33
PLAINTEXT_BLOCK_SIZE = 31
DEFAULT_E = 65537
MILLER_RABIN_ROUNDS = 16


class BigUInt:
	"""固定长度 33 字节、基数 256 的无符号大整数表示。"""

	__slots__ = ("digits",)

	def __init__(self, digits: list[int] | None = None):
		if digits is None:
			self.digits = [0] * SIZE
			return
		if len(digits) != SIZE:
			raise ValueError(f"大整数数组长度必须为 {SIZE}")
		self.digits = [int(byte) & 0xFF for byte in digits]

	@classmethod
	def from_int(cls, value: int, size: int = SIZE) -> "BigUInt":
		if value < 0:
			raise ValueError("大整数不能为负数")
		digits = [0] * size
		tmp = value
		for index in range(size):
			digits[index] = tmp & 0xFF
			tmp >>= 8
		if tmp:
			raise ValueError(f"整数超出 {size} 字节表示范围")
		return cls(digits)

	def to_int(self) -> int:
		value = 0
		for byte in reversed(self.digits):
			value = (value << 8) | byte
		return value

	def to_bytes(self) -> bytes:
		return bytes(reversed(self.digits))

	def to_hex_pairs(self) -> str:
		return " ".join(f"{byte:02X}" for byte in self.to_bytes())

	def to_hex(self) -> str:
		return "".join(f"{byte:02X}" for byte in self.to_bytes())

	def __str__(self) -> str:
		return self.to_hex_pairs()

	def __repr__(self) -> str:
		return f"BigUInt({self.to_hex_pairs()})"


class RSA:
	"""教学演示版 RSA：随机 128bit 素数 + UTF-8 分块加解密。"""

	@staticmethod
	def gcd(a: int, b: int) -> int:
		while b:
			a, b = b, a % b
		return abs(a)

	@staticmethod
	def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
		if b == 0:
			return abs(a), 1 if a >= 0 else -1, 0
		g, x1, y1 = RSA.extended_gcd(b, a % b)
		return g, y1, x1 - (a // b) * y1

	@staticmethod
	def mod_inverse(e: int, phi: int) -> int:
		g, x, _ = RSA.extended_gcd(e, phi)
		if g != 1:
			raise ValueError("e 与 phi(n) 不互素，无法求出私钥 d")
		return x % phi

	@staticmethod
	def _is_probable_prime(n: int, rounds: int = MILLER_RABIN_ROUNDS) -> bool:
		if n < 2:
			return False
		for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
			if n == small:
				return True
			if n % small == 0:
				return n == small
		d = n - 1
		s = 0
		while d % 2 == 0:
			d //= 2
			s += 1

		for _ in range(rounds):
			a = secrets.randbelow(n - 3) + 2
			x = pow(a, d, n)
			if x in (1, n - 1):
				continue
			for _ in range(s - 1):
				x = pow(x, 2, n)
				if x == n - 1:
					break
			else:
				return False
		return True

	@classmethod
	def _random_128bit_odd(cls) -> int:
		candidate = secrets.randbits(128)
		candidate |= (1 << 127)
		candidate |= 1
		return candidate

	@classmethod
	def _random_prime_128bit(cls) -> int:
		while True:
			candidate = cls._random_128bit_odd()
			if cls._is_probable_prime(candidate):
				return candidate

	@staticmethod
	def _normalize_key_input(key_or_p, q=None, e=None) -> tuple[int, int, int]:
		if q is None and e is None:
			if not isinstance(key_or_p, dict):
				raise TypeError("需要传入密钥字典，或传入 p、q、e 三个整数")
			return int(key_or_p["p_int"]), int(key_or_p["q_int"]), int(key_or_p["e_int"])
		if q is None or e is None:
			raise TypeError("必须同时提供 p、q、e")
		return int(key_or_p), int(q), int(e)

	def generate_key_material(self, p: int | None = None, q: int | None = None, e: int = DEFAULT_E) -> dict[str, object]:
		random_mode = p is None and q is None
		if random_mode:
			while True:
				p_int = self._random_prime_128bit()
				q_int = self._random_prime_128bit()
				if p_int == q_int:
					continue
				phi_int = (p_int - 1) * (q_int - 1)
				if self.gcd(e, phi_int) != 1:
					continue
				n_int = p_int * q_int
				d_int = self.mod_inverse(e, phi_int)
				break
		else:
			if p is None or q is None:
				raise ValueError("p 和 q 不能只提供一个")
			p_int = int(p)
			q_int = int(q)
			if p_int == q_int:
				raise ValueError("p 和 q 不能相同")
			if p_int < 2 or q_int < 2:
				raise ValueError("p 和 q 必须大于 1")
			if not self._is_probable_prime(p_int):
				raise ValueError("p 不是素数")
			if not self._is_probable_prime(q_int):
				raise ValueError("q 不是素数")
			phi_int = (p_int - 1) * (q_int - 1)
			if e <= 1 or e >= phi_int:
				raise ValueError("e 必须满足 1 < e < phi(n)")
			if self.gcd(e, phi_int) != 1:
				raise ValueError("e 与 phi(n) 不互素")
			n_int = p_int * q_int
			d_int = self.mod_inverse(e, phi_int)

		return {
			"p_int": p_int,
			"q_int": q_int,
			"e_int": e,
			"d_int": d_int,
			"n_int": n_int,
			"phi_int": phi_int,
			"p": BigUInt.from_int(p_int),
			"q": BigUInt.from_int(q_int),
			"e": BigUInt.from_int(e),
			"d": BigUInt.from_int(d_int),
			"n": BigUInt.from_int(n_int),
			"phi": BigUInt.from_int(phi_int),
			"block_size": PLAINTEXT_BLOCK_SIZE,
			"cipher_block_size": SIZE,
		}

	@staticmethod
	def _pad(data: bytes, block_size: int) -> bytes:
		pad_len = (-len(data)) % block_size
		if pad_len == 0:
			return data
		return data + bytes(pad_len)

	@staticmethod
	def _unpad_length_prefixed(data: bytes) -> bytes:
		if len(data) < 4:
			raise ValueError("解密结果长度不足，无法恢复原文")
		original_len = int.from_bytes(data[:4], "big")
		if original_len < 0 or original_len > len(data) - 4:
			raise ValueError("解密结果中的长度标记无效")
		return data[4:4 + original_len]

	@staticmethod
	def _parse_ciphertext_tokens(ciphertext_text: str) -> list[str]:
		tokens: list[str] = []
		for line in ciphertext_text.splitlines():
			tokens.extend(part for part in line.replace(",", " ").split() if part)
		return tokens

	def encrypt(self, plaintext: str, key_or_p, q=None, e=None) -> tuple[str, dict[str, object]]:
		p_int, q_int, e_int = self._normalize_key_input(key_or_p, q, e)
		key = self.generate_key_material(p_int, q_int, e_int)
		data = plaintext.encode("utf-8")
		prefixed = len(data).to_bytes(4, "big") + data
		prefixed = self._pad(prefixed, PLAINTEXT_BLOCK_SIZE)

		encrypted_blocks: list[str] = []
		for start in range(0, len(prefixed), PLAINTEXT_BLOCK_SIZE):
			block = prefixed[start:start + PLAINTEXT_BLOCK_SIZE]
			message_int = int.from_bytes(block, "big")
			if message_int >= key["n_int"]:
				raise ValueError("明文块超出模数范围，请换用更大的 p / q")
			cipher_int = pow(message_int, key["e_int"], key["n_int"])
			encrypted_blocks.append(BigUInt.from_int(cipher_int).to_hex())

		return "\n".join(encrypted_blocks), key

	def decrypt(self, ciphertext_text: str, key_or_p, q=None, e=None) -> tuple[str, dict[str, object]]:
		p_int, q_int, e_int = self._normalize_key_input(key_or_p, q, e)
		key = self.generate_key_material(p_int, q_int, e_int)
		tokens = self._parse_ciphertext_tokens(ciphertext_text)
		if not tokens:
			raise ValueError("请输入密文块")

		decrypted = bytearray()
		for token in tokens:
			cipher_int = int(token.replace(" ", ""), 16)
			if cipher_int < 0 or cipher_int >= key["n_int"]:
				raise ValueError("密文块超出模数范围")
			message_int = pow(cipher_int, key["d_int"], key["n_int"])
			decrypted.extend(message_int.to_bytes(PLAINTEXT_BLOCK_SIZE, "big"))

		restored = self._unpad_length_prefixed(bytes(decrypted))
		return restored.decode("utf-8"), key


class RSAApp:
	def __init__(self, root: tk.Tk):
		self.root = root
		self.root.title("RSA 加解密工具")
		self.root.geometry("1000x820")
		self.root.minsize(940, 720)
		self.root.configure(bg="#f5f7fb")

		self.rsa = RSA()
		self.current_key = self.rsa.generate_key_material()

		title_font = ("Microsoft YaHei", 16, "bold")
		label_font = ("Microsoft YaHei", 10, "bold")
		text_font = ("Consolas", 11)

		header = tk.Frame(root, bg="#f5f7fb")
		header.pack(fill=tk.X, padx=20, pady=(18, 8))
		tk.Label(header, text="RSA 加解密程序", font=title_font, bg="#f5f7fb", fg="#1f2d3d").pack(anchor="w")
		tk.Label(
			header,
			text="每次随机生成 128bit 的 p 和 q，e 固定为 65537。",
			font=("Microsoft YaHei", 9),
			bg="#f5f7fb",
			fg="#5c677d",
		).pack(anchor="w", pady=(4, 0))

		form = tk.Frame(root, bg="#f5f7fb")
		form.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

		key_frame = tk.LabelFrame(form, text="密钥参数", font=label_font, bg="#f5f7fb", padx=10, pady=10)
		key_frame.pack(fill=tk.X, pady=(0, 10))

		tk.Button(
			key_frame,
			text="随机生成密钥",
			command=self.handle_generate_keys,
			width=16,
			font=("Microsoft YaHei", 10, "bold"),
			bg="#f2994a",
			fg="white",
			activebackground="#db7f2e",
			relief=tk.FLAT,
			padx=10,
			pady=6,
		).pack(anchor="w")

		tk.Label(key_frame, text="当前密钥（基数 256，无符号字节数组，SIZE=33）", font=("Microsoft YaHei", 9), bg="#f5f7fb", fg="#666666").pack(anchor="w", pady=(10, 4))
		self.key_info_display = tk.Text(key_frame, height=5, font=("Consolas", 9), relief=tk.SUNKEN, bd=1, bg="#eeeeee", state=tk.DISABLED)
		self.key_info_display.pack(fill=tk.X)

		btn_frame = tk.LabelFrame(form, text="操作区", font=label_font, bg="#f5f7fb", padx=10, pady=12)
		btn_frame.pack(fill=tk.X, pady=(0, 10))

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

		panes = tk.Frame(form, bg="#f5f7fb")
		panes.pack(fill=tk.BOTH, expand=True)

		left_panel = tk.LabelFrame(panes, text="明文框", font=label_font, bg="#f5f7fb", padx=10, pady=10)
		right_panel = tk.LabelFrame(panes, text="密文框", font=label_font, bg="#f5f7fb", padx=10, pady=10)
		left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
		right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))

		self.plain_text = scrolledtext.ScrolledText(left_panel, font=text_font, height=12, wrap=tk.WORD)
		self.plain_text.pack(fill=tk.BOTH, expand=True)
		self.plain_text.insert(tk.END, "Hi, this is RSA!")

		self.cipher_text = scrolledtext.ScrolledText(right_panel, font=text_font, height=12, wrap=tk.WORD)
		self.cipher_text.pack(fill=tk.BOTH, expand=True)

		decrypt_frame = tk.LabelFrame(form, text="解密文框", font=label_font, bg="#f5f7fb", padx=10, pady=10)
		decrypt_frame.pack(fill=tk.BOTH, expand=True, pady=(14, 0))
		self.decrypt_text = scrolledtext.ScrolledText(decrypt_frame, font=text_font, height=8, wrap=tk.WORD)
		self.decrypt_text.pack(fill=tk.BOTH, expand=True)

		self.update_key_info_display()

	@staticmethod
	def _get_text(widget: tk.Text) -> str:
		return widget.get("1.0", tk.END).strip()

	@staticmethod
	def _set_text(widget: tk.Text, value: str) -> None:
		widget.delete("1.0", tk.END)
		widget.insert(tk.END, value)

	def update_key_info_display(self) -> None:
		key = self.current_key
		text = (
			f"p = {key['p_int']}\n"
			f"q = {key['q_int']}\n"
			f"n = {key['n_int']}\n"
			f"e = {key['e_int']}\n"
			f"d = {key['d_int']}\n"
		)
		self.key_info_display.config(state=tk.NORMAL)
		self.key_info_display.delete("1.0", tk.END)
		self.key_info_display.insert(tk.END, text)
		self.key_info_display.config(state=tk.DISABLED)

	def handle_generate_keys(self) -> None:
		try:
			self.current_key = self.rsa.generate_key_material()
			self.update_key_info_display()
		except Exception as exc:
			messagebox.showerror("密钥生成失败", str(exc))

	def handle_encrypt(self) -> None:
		plaintext = self._get_text(self.plain_text)
		if not plaintext:
			messagebox.showwarning("提示", "请输入明文。")
			return

		try:
			ciphertext, _ = self.rsa.encrypt(plaintext, self.current_key)
			self._set_text(self.cipher_text, ciphertext)
			self._set_text(self.decrypt_text, "")
		except Exception as exc:
			messagebox.showerror("加密失败", str(exc))

	def handle_decrypt(self) -> None:
		ciphertext = self._get_text(self.cipher_text)
		if not ciphertext:
			messagebox.showwarning("提示", "请输入密文。")
			return

		try:
			plaintext, _ = self.rsa.decrypt(ciphertext, self.current_key)
			self._set_text(self.decrypt_text, plaintext)
		except ValueError as exc:
			messagebox.showerror("解密失败", str(exc))
		except UnicodeDecodeError:
			messagebox.showerror("解密失败", "解密结果不是有效的 UTF-8 文本，请检查密文或密钥是否正确。")
		except Exception as exc:
			messagebox.showerror("解密失败", str(exc))

	def handle_clear(self) -> None:
		self._set_text(self.plain_text, "")
		self._set_text(self.cipher_text, "")
		self._set_text(self.decrypt_text, "")


if __name__ == "__main__":
	root = tk.Tk()
	app = RSAApp(root)
	root.mainloop()
