# chat_ui.py
import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
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
        self.sock = None

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TButton", padding=6, relief="flat", background="#3a3f44", foreground="white")

        self.frame = tk.Frame(root, bg="#1e1e1e")
        self.frame.pack(padx=10, pady=10)

        self.text_widget = tk.Text(self.frame, bg="#2d2d2d", fg="white", state='disabled', height=20, width=50)
        self.text_widget.pack(pady=(0, 10))

        self.entry = tk.Entry(self.frame, bg="#3a3f44", fg="white")
        self.entry.pack(fill=tk.X)
        self.entry.bind("<Return>", self.send_message)

        self.button_frame = tk.Frame(self.frame, bg="#1e1e1e")
        self.button_frame.pack(pady=(10, 0))

        ttk.Button(self.button_frame, text="Server starten", command=self.start_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="Mit Server verbinden", command=self.connect_to_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="🔒 Secure All", command=self.secure_delete).pack(side=tk.LEFT, padx=5)

        self.dropdown_frame = tk.Frame(self.frame, bg="#1e1e1e")
        self.dropdown_frame.pack(pady=(10, 0))

        self.connections = load_connections()
        self.selected_conn = tk.StringVar()
        self.dropdown = ttk.Combobox(self.dropdown_frame, textvariable=self.selected_conn, values=list(self.connections.keys()), state='readonly')
        self.dropdown.pack(side=tk.LEFT)
        ttk.Button(self.dropdown_frame, text="Verbinden", command=self.connect_saved).pack(side=tk.LEFT, padx=5)

        self.version_label = tk.Label(self.frame, text=VERSION, bg="#1e1e1e", fg="#888888")
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

    def connect_saved(self):
        name = self.selected_conn.get()
        if not name:
            return
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

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(1024)
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
