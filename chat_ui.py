# chat_ui.py
import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, filedialog
import json
import os
from cryptography.fernet import Fernet

# === Konfiguration ===
KEY = Fernet.generate_key()  # Ersetze durch deinen festen Key bei Bedarf
VERSION = "v1.3.0"
PORT = 12345
connections_file = "connections.json"
cipher = Fernet(KEY)

# === Verbindung speichern/laden ===
def load_connections():
    if not os.path.exists(connections_file):
        with open(connections_file, 'w') as f:
            json.dump({}, f)
    with open(connections_file, 'r') as f:
        return json.load(f)

def save_connection(name, ip):
    connections = load_connections()
    connections[name] = ip
    with open(connections_file, 'w') as f:
        json.dump(connections, f)

# === Chatfenster ===
class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AncronSecure Chat")
        self.root.configure(bg="#1e1e1e")
        self.root.state('zoomed')
        self.sock = None

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TButton", padding=6, relief="flat", background="#3a3f44", foreground="white")

        self.main_frame = tk.Frame(root, bg="#1e1e1e")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.sidebar = tk.Frame(self.main_frame, bg="#2a2a2a", width=200)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)

        self.chat_area = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.chat_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.connection_buttons = []
        self.connections = load_connections()
        for name in self.connections:
            btn = ttk.Button(self.sidebar, text=name, command=lambda n=name: self.switch_to_connection(n))
            btn.pack(fill=tk.X, pady=2, padx=5)
            self.connection_buttons.append(btn)

        self.text_widget = tk.Text(self.chat_area, bg="#2d2d2d", fg="white", state='disabled', height=20)
        self.text_widget.pack(pady=(10, 10), fill=tk.BOTH, expand=True)

        self.entry = tk.Entry(self.chat_area, bg="#3a3f44", fg="white")
        self.entry.pack(fill=tk.X, padx=10)
        self.entry.bind("<Return>", self.send_message)

        self.button_frame = tk.Frame(self.chat_area, bg="#1e1e1e")
        self.button_frame.pack(pady=(10, 0))

        ttk.Button(self.button_frame, text="Server starten", command=self.start_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="Mit Server verbinden", command=self.connect_to_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="🔒 Secure All", command=self.secure_delete).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="📁 Bild senden (bis 4K)", command=self.send_image).pack(side=tk.LEFT, padx=5)

        self.version_label = tk.Label(self.chat_area, text=f"Ancron4K System - {VERSION}", bg="#1e1e1e", fg="#888888")
        self.version_label.pack(anchor='se', padx=5, pady=(20, 0))

        self.append_message("Willkommen bei AncronSecure Chat \U0001F512", "System")

    def append_message(self, message, sender=""):
        self.text_widget.config(state='normal')
        tag = "user" if sender else None
        self.text_widget.insert(tk.END, f"{sender}: {message}\n" if sender else f"{message}\n", tag)
        self.text_widget.config(state='disabled')
        self.text_widget.see(tk.END)

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("", PORT))
        server.listen(1)
        self.append_message("[System] Warte auf Verbindung...")

        def handle_client():
            conn, addr = server.accept()
            self.sock = conn
            self.append_message(f"[System] Verbunden mit {addr[0]}")
            threading.Thread(target=self.receive_messages, daemon=True).start()

        threading.Thread(target=handle_client, daemon=True).start()

    def connect_to_server(self):
        ip = simpledialog.askstring("Verbinden", "Gib die IP-Adresse ein:")
        name = simpledialog.askstring("Name speichern", "Speichere diese Verbindung unter welchem Namen?")
        if name and ip:
            save_connection(name, ip)
        self._connect(ip)

    def switch_to_connection(self, name):
        ip = self.connections.get(name)
        if ip and messagebox.askyesno("Sicher?", f"Verbindest du dich mit {ip}?\n\n⚠️ Dies kann ein Phishing-Risiko darstellen."):
            self._connect(ip)

    def _connect(self, ip):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((ip, PORT))
            self.append_message(f"[System] Verbunden mit {ip}")
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Fehler", f"Verbindung fehlgeschlagen: {e}")

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg and self.sock:
            encrypted = cipher.encrypt(msg.encode())
            self.sock.send(encrypted)
            self.append_message(msg, "Du")
            self.entry.delete(0, tk.END)

    def send_image(self):
        if not self.sock:
            return
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if path:
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                label = f"[Bild gesendet: {os.path.basename(path)} ({len(data)//1024} KB)]"
                self.sock.send(cipher.encrypt(label.encode()))
                self.append_message(label, "Du")
            except Exception as e:
                messagebox.showerror("Fehler", f"Bild konnte nicht gesendet werden: {e}")

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                decrypted = cipher.decrypt(data).decode()
                if decrypted == "__SECURE_DELETE__":
                    self.secure_delete_remote()
                else:
                    self.append_message(decrypted, "Partner")
            except:
                break

    def secure_delete(self):
        if self.sock:
            self.sock.send(cipher.encrypt(b"__SECURE_DELETE__"))
        self.text_widget.config(state='normal')
        self.text_widget.delete("1.0", tk.END)
        self.text_widget.config(state='disabled')
        self.append_message("🧹 Chatverlauf gelöscht. Stay safe.", "System")

    def secure_delete_remote(self):
        if messagebox.askyesno("Löschen?", "Der Partner fordert das Löschen des Chatverlaufs an. Zustimmen?"):
            self.text_widget.config(state='normal')
            self.text_widget.delete("1.0", tk.END)
            self.text_widget.config(state='disabled')
            self.append_message("🧹 Partner hat den Chat gelöscht. Stay safe.", "System")

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
