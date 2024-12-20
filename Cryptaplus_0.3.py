import tkinter as tk
from tkinter import messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
import secrets
import pyperclip

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encriptador y Desencriptador de Mensajes")
        self.root.geometry("800x600")
        
        # Configurar estilo
        style = ttk.Style()
        style.configure("TButton", padding=6)
        style.configure("TLabel", font=("Arial", 10))
        
        self.create_widgets()
        self.create_context_menu()
        
    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Mensaje
        ttk.Label(main_frame, text="Mensaje:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.message_text = tk.Text(main_frame, width=60, height=10)
        self.message_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        self.message_text.bind("<Button-3>", self.show_context_menu)
        
        # Clave
        ttk.Label(main_frame, text="Clave:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.key_frame = ttk.Frame(main_frame)
        self.key_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.key_entry = ttk.Entry(self.key_frame, show="*", width=50)
        self.key_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.key_entry.bind("<Button-3>", self.show_context_menu)
        
        # Botón para mostrar/ocultar clave
        self.show_key_var = tk.BooleanVar()
        self.show_key_btn = ttk.Checkbutton(self.key_frame, text="Mostrar", 
                                           variable=self.show_key_var, 
                                           command=self.toggle_key_visibility)
        self.show_key_btn.pack(side=tk.LEFT, padx=5)
        
        # Botones
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Encriptar", command=self.encrypt_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Desencriptar", command=self.decrypt_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Limpiar Campos", command=self.clear_fields).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copiar al Portapapeles", command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        
        # Etiqueta de resultado
        self.result_label = ttk.Label(main_frame, text="")
        self.result_label.grid(row=5, column=0, columnspan=2, pady=10)
        
    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copiar", command=self.copy_selection)
        self.context_menu.add_command(label="Cortar", command=self.cut_selection)
        self.context_menu.add_command(label="Pegar", command=self.paste_selection)
        
    def show_context_menu(self, event):
        widget = event.widget
        self.active_widget = widget
        self.context_menu.tk_popup(event.x_root, event.y_root)
        
    def copy_selection(self):
        try:
            self.active_widget.event_generate("<<Copy>>")
        except:
            pass
            
    def cut_selection(self):
        try:
            self.active_widget.event_generate("<<Cut>>")
        except:
            pass
            
    def paste_selection(self):
        try:
            self.active_widget.event_generate("<<Paste>>")
        except:
            pass
            
    def toggle_key_visibility(self):
        if self.show_key_var.get():
            self.key_entry.configure(show="")
        else:
            self.key_entry.configure(show="*")
            
    def get_hashed_key(self, key):
        hasher = SHA256.new()
        hasher.update(key.encode('utf-8'))
        return hasher.digest()
        
    def encrypt_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        key = self.key_entry.get()
        
        if not message or not key:
            messagebox.showwarning("Advertencia", 
                                 "Por favor, introduce tanto el mensaje como la clave.")
            return
            
        try:
            hashed_key = self.get_hashed_key(key)
            cipher = AES.new(hashed_key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
            iv = b64encode(cipher.iv).decode('utf-8')
            ct = b64encode(ct_bytes).decode('utf-8')
            encrypted_message = iv + ct
            
            self.message_text.delete("1.0", tk.END)
            self.message_text.insert(tk.END, encrypted_message)
            self.result_label.config(text="Mensaje Encriptado")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error durante la encriptación: {str(e)}")
            
    def decrypt_message(self):
        encrypted_message = self.message_text.get("1.0", tk.END).strip()
        key = self.key_entry.get()
        
        if not encrypted_message or not key:
            messagebox.showwarning("Advertencia", 
                                 "Por favor, introduce tanto el mensaje encriptado como la clave.")
            return
            
        try:
            hashed_key = self.get_hashed_key(key)
            iv = b64decode(encrypted_message[:24])
            ct = b64decode(encrypted_message[24:])
            cipher = AES.new(hashed_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            decrypted_message = pt.decode('utf-8')
            
            self.message_text.delete("1.0", tk.END)
            self.message_text.insert(tk.END, decrypted_message)
            self.result_label.config(text="Mensaje Desencriptado")
            
        except Exception as e:
            messagebox.showerror("Error", "Clave incorrecta o mensaje corrupto")
            
    def clear_fields(self):
        self.message_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.result_label.config(text="")
        
    def copy_to_clipboard(self):
        text = self.message_text.get("1.0", tk.END).strip()
        if text:
            pyperclip.copy(text)
            self.result_label.config(text="Texto copiado al portapapeles")
        else:
            messagebox.showwarning("Advertencia", "No hay texto para copiar")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()