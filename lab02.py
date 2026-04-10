import tkinter as tk
from tkinter import messagebox

def rc4_logic(data_bytes, key_string):
    """RC4 核心算法实现"""
    key_bytes = key_string.encode('utf-8')
    S = list(range(256))
    j = 0
    # KSA 阶段
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # PRGA 阶段与 XOR
    i = j = 0
    res = []
    keystream = []
    for char_byte in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        keystream.append(k)
        res.append(char_byte ^ k)
    return bytes(res), bytes(keystream)

class StringRC4App:
    def __init__(self, root):
        self.root = root
        self.root.title("RC4 字符串加密工具")
        self.root.geometry("500x550")
        self.root.configure(bg="#f5f5f5")

        # 字体设置
        label_font = ("Microsoft YaHei", 10, "bold")

        # 密钥
        tk.Label(root, text="密钥", font=label_font, bg="#f5f5f5").pack(pady=(10,0))
        self.key_entry = tk.Entry(root, width=50, font=("Consolas", 10))
        self.key_entry.insert(0, "my_secret_key")
        self.key_entry.pack(pady=5)

        # 明文/密文输入
        tk.Label(root, text="输入", font=label_font, bg="#f5f5f5").pack(pady=(10,0))
        self.input_box = tk.Text(root, height=6, width=60, font=("Consolas", 10))
        self.input_box.pack(pady=5)

        # 按钮
        btn_frame = tk.Frame(root, bg="#f5f5f5")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="加密", command=self.do_encrypt, bg="#4CAF50", fg="white", width=15).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="解密", command=self.do_decrypt, bg="#2196F3", fg="white", width=15).pack(side=tk.LEFT, padx=10)

        # 密钥流显示
        tk.Label(root, text="密钥流", font=label_font, bg="#f5f5f5").pack()
        self.ks_box = tk.Text(root, height=3, width=60, bg="#eeeeee", state=tk.DISABLED, font=("Consolas", 9))
        self.ks_box.pack(pady=5)

        # 结果
        tk.Label(root, text="输出", font=label_font, bg="#f5f5f5").pack()
        self.result_box = tk.Text(root, height=6, width=60, bg="#ffffff", font=("Consolas", 10))
        self.result_box.pack(pady=5)

    def update_ks_display(self, ks_bytes):
        """显示密钥流"""
        self.ks_box.config(state=tk.NORMAL)
        self.ks_box.delete("1.0", tk.END)
        self.ks_box.insert(tk.END, ks_bytes.hex(' ').upper())
        self.ks_box.config(state=tk.DISABLED)

    def do_encrypt(self):
        key = self.key_entry.get()
        plaintext = self.input_box.get("1.0", tk.END).strip()
        if not key or not plaintext:
            return messagebox.showwarning("提示", "密钥和明文不能为空")

        # 字符串转字节后加密
        ciphertext, ks = rc4_logic(plaintext.encode('utf-8'), key)
        self.update_ks_display(ks)
        
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, ciphertext.hex().upper())

    def do_decrypt(self):
        key = self.key_entry.get()
        hex_input = self.input_box.get("1.0", tk.END).strip().replace(" ", "")
        if not key or not hex_input:
            return messagebox.showwarning("提示", "密钥和待解密Hex不能为空")

        try:
            cipher_bytes = bytes.fromhex(hex_input)
            original_bytes, ks = rc4_logic(cipher_bytes, key)
            self.update_ks_display(ks)

            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, original_bytes.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}\n请确保输入的是正确的十六进制字符串。")

if __name__ == "__main__":
    window = tk.Tk()
    app = StringRC4App(window)
    window.mainloop()