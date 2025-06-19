import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import socket
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

PORT = 12345
KEY = b'\x01'*32  # 32 Bytes Schlüssel (für Demo hardcoded, tausche das sicher aus!)

class SecureChat(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure SecureChat")
        self.geometry("500x420")

        self.chat_log = scrolledtext.ScrolledText(self, state='disabled')
        self.chat_log.pack(expand=True, fill='both', padx=10, pady=10)

        self.status_label = tk.Label(self, text="Status: offline")
        self.status_label.pack(padx=10)

        self.entry = tk.Entry(self)
        self.entry.pack(fill='x', padx=10, pady=5)
        self.entry.bind("<KeyPress>", self.notify_typing)
        self.entry.bind("<Return>", self.send_message)

        send_btn = tk.Button(self, text="Senden", command=self.send_message)
        send_btn.pack(padx=10, pady=5)

        frame = tk.Frame(self)
        frame.pack(pady=5)
        self.server_btn = tk.Button(frame, text="Server starten", command=self.start_server)
        self.server_btn.pack(side='left', padx=5)
        self.client_btn = tk.Button(frame, text="Mit Server verbinden", command=self.connect_to_server)
        self.client_btn.pack(side='left', padx=5)

        self.sock = None
        self.conn = None
        self.running = False
        self.aesgcm = AESGCM(KEY)
        self.last_typing = 0
        self.typing_timeout = 2  # Sekunden
        self.typing_active = False

    def start_server(self):
        if self.running:
            messagebox.showinfo("Info", "Server läuft bereits!")
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('', PORT))
        self.sock.listen(1)
        self.append_chat("Server läuft. Warte auf Verbindung...")
        threading.Thread(target=self.accept_connection, daemon=True).start()
        self.running = True
        self.update_status("Warte auf Verbindung...")

    def accept_connection(self):
        try:
            self.conn, addr = self.sock.accept()
            self.append_chat(f"Verbindung von {addr} hergestellt!")
            self.update_status("Verbunden")
            self.send_encrypted(b"__STATUS__ONLINE__")
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.append_chat(f"Fehler beim Akzeptieren: {e}")
            self.update_status("Fehler")

    def connect_to_server(self):
        if self.running:
            messagebox.showinfo("Info", "Bereits verbunden!")
            return
        ip = simpledialog.askstring("IP-Adresse eingeben", "Gib die IP des Servers ein:")
        if not ip:
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((ip, PORT))
            self.append_chat(f"Mit Server {ip} verbunden!")
            self.running = True
            self.update_status("Verbunden")
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.send_encrypted(b"__STATUS__ONLINE__")
        except Exception as e:
            messagebox.showerror("Fehler", f"Verbindung fehlgeschlagen: {e}")
            self.update_status("Fehler")

    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if not msg or not self.running:
            return
        self.entry.delete(0, tk.END)
        self.append_chat(f"Du: {msg}")
        self.send_encrypted(msg.encode('utf-8'))
        self.typing_active = False
        self.send_encrypted(b"__STATUS__NOTYPING__")

    def notify_typing(self, event=None):
        if not self.running:
            return
        now = time.time()
        if now - self.last_typing > self.typing_timeout:
            self.send_encrypted(b"__STATUS__TYPING__")
            self.typing_active = True
        self.last_typing = now
        self.after(int(self.typing_timeout * 1000), self.check_typing_timeout)

    def check_typing_timeout(self):
        if time.time() - self.last_typing > self.typing_timeout and self.typing_active:
            self.send_encrypted(b"__STATUS__NOTYPING__")
            self.typing_active = False

    def send_encrypted(self, data: bytes):
        nonce = os.urandom(12)
        encrypted = self.aesgcm.encrypt(nonce, data, None)
        packet = nonce + encrypted
        try:
            if self.conn:
                self.conn.sendall(packet)
            else:
                self.sock.sendall(packet)
        except Exception as e:
            self.append_chat(f"Fehler beim Senden: {e}")

    def receive_messages(self):
        sock = self.conn if self.conn else self.sock
        try:
            while True:
                packet = sock.recv(1024)
                if not packet:
                    self.append_chat("Verbindung getrennt.")
                    self.update_status("Offline")
                    break
                nonce = packet[:12]
                encrypted = packet[12:]
                try:
                    data = self.aesgcm.decrypt(nonce, encrypted, None)
                    self.process_message(data)
                except Exception:
                    self.append_chat("[!] Nachricht konnte nicht entschlüsselt werden")
        except Exception as e:
            self.append_chat(f"Verbindungsfehler: {e}")
            self.update_status("Offline")
        finally:
            self.running = False
            if self.conn:
                self.conn.close()
            if self.sock:
                self.sock.close()

    def process_message(self, data: bytes):
        msg = data.decode('utf-8')
        if msg == "__STATUS__ONLINE__":
            self.update_status("Gegner online")
        elif msg == "__STATUS__TYPING__":
            self.status_label.config(text="Status: Gegner schreibt...")
        elif msg == "__STATUS__NOTYPING__":
            self.status_label.config(text="Status: Gegner online")
        else:
            self.append_chat(f"Partner: {msg}")

    def append_chat(self, text):
        self.chat_log.config(state='normal')
        self.chat_log.insert(tk.END, text + "\n")
        self.chat_log.config(state='disabled')
        self.chat_log.see(tk.END)

    def update_status(self, text):
        self.status_label.config(text=f"Status: {text}")

if __name__ == "__main__":
    app = SecureChat()
    app.mainloop()
