import tkinter as tk
from tkinter import ttk
import sys

class CaesarCipher(tk.Frame):
    def __init__(self, root):
        # Updated Color Scheme
        self.bg_color = "#2C3E50"  # Dark Blue Background
        self.text_color = "#FF4040"  # Red Font
        self.button_color = "#3498DB"  # Blue Buttons
        self.hover_color = "#2980B9"  # Button Hover Color
        self.entry_color = "#1ABC9C"  # Teal Entry Background
        self.invalid_key_color = "#E74C3C"  # Red for invalid input
        
        self.letters = 'abcdefghijklmnopqrstuvwxyz'
        self.num_letters = len(self.letters)
        
        super().__init__(root, bg=self.bg_color)
        self.main_frame = self
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame.columnconfigure(0, weight=1)
        
        self.render_widgets()

    def render_widgets(self):
        # Title
        self.title = tk.Label(
            self.main_frame, text="Caesar Cipher",
            bg=self.bg_color, fg=self.text_color,
            font=("Helvetica", 26, "bold")
        )
        self.title.grid(column=0, row=0, pady=20)

        # Text Input
        self.text_widget = tk.Text(
            self.main_frame, bg=self.entry_color, fg=self.bg_color,
            font=("Consolas", 15), height=6, padx=10, pady=10,
            highlightthickness=0, borderwidth=0, wrap="word"
        )
        self.text_widget.grid(column=0, row=1, padx=40, pady=10)

        # Key Entry with Validation
        self.key_label = tk.Label(
            self.main_frame, text="Key (1-26):",
            bg=self.bg_color, fg=self.text_color,
            font=("Helvetica", 12, "bold")
        )
        self.key_label.grid(column=0, row=2, pady=10)
        
        # Validation Command for Key Entry
        vcmd = (self.register(self.validate_key_input), "%P")

        self.key_entry = tk.Entry(
            self.main_frame, bg=self.text_color, fg=self.bg_color,
            font=("Consolas", 14), justify="center", width=5,
            validate="key", validatecommand=vcmd,  # Real-time validation
            highlightthickness=2, highlightbackground=self.bg_color
        )
        self.key_entry.grid(column=0, row=3, pady=5)

        # Buttons Frame
        self.buttons_container = tk.Frame(self.main_frame, bg=self.bg_color)
        self.buttons_container.grid(column=0, row=4, pady=20)

        self.button_encrypt = ttk.Button(
            self.buttons_container, text="Encrypt",
            command=self.encrypt_command, style="Cipher.TButton"
        )
        self.button_encrypt.grid(column=0, row=0, padx=10, ipadx=10)

        self.button_decrypt = ttk.Button(
            self.buttons_container, text="Decrypt",
            command=self.decrypt_command, style="Cipher.TButton"
        )
        self.button_decrypt.grid(column=1, row=0, padx=10, ipadx=10)
        
        # Styling the Buttons
        self.style = ttk.Style()
        self.style.configure("Cipher.TButton", 
            font=("Helvetica", 14, "bold"), 
            background=self.button_color, 
            foreground=self.text_color,
            padding=6
        )
        self.style.map("Cipher.TButton", 
            background=[("active", self.hover_color)], 
            foreground=[("active", self.text_color)]
        )

    def validate_key_input(self, new_value):
        """
        Validate key input:
        1. Allow only numeric input.
        2. Restrict to 2 digits (max 26).
        """
        if new_value == "" or new_value.isdigit():  # Only digits allowed
            if new_value == "" or (1 <= int(new_value) <= 26):
                return True  # Accept valid input
        return False  # Reject invalid input

    def encrypt_decrypt(self, text, key, mode):
        """ Generalized method for encryption/decryption """
        result = ''
        for letter in text.lower():
            if letter in self.letters:
                index = self.letters.find(letter)
                if mode == 'encrypt':
                    new_index = (index + key) % self.num_letters
                else:
                    new_index = (index - key) % self.num_letters
                result += self.letters[new_index]
            else:
                result += letter
        return result

    def show_result(self, result):
        """ Display result in the text widget with animation effect """
        self.text_widget.delete("1.0", tk.END)
        for i, char in enumerate(result):
            self.text_widget.insert(f"{i + 1}.0", char)
            self.text_widget.update()
            self.text_widget.after(5)  # Animation delay

    def encrypt_command(self):
        """ Command to encrypt text """
        try:
            key = int(self.key_entry.get())
            text = self.text_widget.get("1.0", tk.END).strip()
            result = self.encrypt_decrypt(text, key, "encrypt")
            self.show_result(result)
        except ValueError:
            self.text_widget.delete("1.0", tk.END)
            self.text_widget.insert("1.0", "Invalid key. Please enter a number between 1-26.")

    def decrypt_command(self):
        """ Command to decrypt text """
        try:
            key = int(self.key_entry.get())
            text = self.text_widget.get("1.0", tk.END).strip()
            result = self.encrypt_decrypt(text, key, "decrypt")
            self.show_result(result)
        except ValueError:
            self.text_widget.delete("1.0", tk.END)
            self.text_widget.insert("1.0", "Invalid key. Please enter a number between 1-26.")

# Initialize the GUI
operating_system = sys.platform
root = tk.Tk()
root.title("Caesar Cipher")

# Platform-specific adjustments
if 'win' in operating_system:
    root.geometry("700x500")
else:
    root.geometry("700x500")

root.resizable(False, False)
Caesar_Cipher_app = CaesarCipher(root)
root.mainloop()
