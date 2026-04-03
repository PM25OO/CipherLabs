import tkinter as tk
from tkinter import messagebox

def caesar_cipher(text, shift, mode='encrypt'):
    """处理凯撒加密和解密的核心逻辑"""
    result = ""
    # 如果是解密模式，位移取反
    if mode == 'decrypt':
        shift = -shift
    
    for char in text:
        if char.isalpha():
            # 处理大写和小写字母
            start = ord('A') if char.isupper() else ord('a')
            # 核心位移公式
            new_char = chr((ord(char) - start + shift) % 26 + start)
            result += new_char
        else:
            # 非字母字符（数字、符号、空格）保持不变
            result += char
    return result

class CaesarApp:
    def __init__(self, root):
        self.root = root
        self.root.title("凯撒密码加密/解密器")
        self.root.geometry("400x450")
        
        # 界面布局
        tk.Label(root, text="输入:", font=("Arial", 10)).pack(pady=5)
        self.input_text = tk.Text(root, height=5, width=45)
        self.input_text.pack(pady=5)

        tk.Label(root, text="密钥:", font=("Arial", 10)).pack(pady=5)
        self.shift_entry = tk.Entry(root)
        self.shift_entry.insert(0, "3")  # 默认密钥为3
        self.shift_entry.pack(pady=5)

        # 按钮容器
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)

        self.encrypt_btn = tk.Button(btn_frame, text="加密", command=self.handle_encrypt, width=10, bg="#4CAF50", fg="white")
        self.encrypt_btn.pack(side=tk.LEFT, padx=10)

        self.decrypt_btn = tk.Button(btn_frame, text="解密", command=self.handle_decrypt, width=10, bg="#2196F3", fg="white")
        self.decrypt_btn.pack(side=tk.LEFT, padx=10)

        tk.Label(root, text="输出:", font=("Arial", 10)).pack(pady=5)
        self.output_text = tk.Text(root, height=5, width=45)
        self.output_text.pack(pady=5)

    def get_shift(self):
        """获取并验证密钥"""
        try:
            return int(self.shift_entry.get())
        except ValueError:
            messagebox.showerror("错误", "密钥必须是一个整数！")
            return None

    def handle_encrypt(self):
        shift = self.get_shift()
        if shift is not None:
            text = self.input_text.get("1.0", tk.END).strip()
            result = caesar_cipher(text, shift, 'encrypt')
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)

    def handle_decrypt(self):
        shift = self.get_shift()
        if shift is not None:
            text = self.input_text.get("1.0", tk.END).strip()
            result = caesar_cipher(text, shift, 'decrypt')
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)

if __name__ == "__main__":
    root = tk.Tk()
    app = CaesarApp(root)
    root.mainloop()