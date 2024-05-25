import socket
import threading
from tkinter import *
from tkinter import PhotoImage, Menu, simpledialog
import tkinter.font as tkFont
import logging
from encryption import get_cipher, encrypt_message, decrypt_message
import emoji
from plyer import notification
import pygame

HOST = '127.0.0.1'
PORT = 12345

logging.basicConfig(filename=r'C:\Users\Rares\Desktop\secure_chat\logs.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

pygame.mixer.init()

themes = {
    "Dark": {
        "bg": "#2c2c2c",
        "fg": "white",
        "entry_bg": "#3c3c3c",
        "entry_fg": "white",
        "button_bg": "#4CAF50",
        "button_fg": "white"
    },
    "Light": {
        "bg": "#ffffff",
        "fg": "black",
        "entry_bg": "#f0f0f0",
        "entry_fg": "black",
        "button_bg": "#4CAF50",
        "button_fg": "black"
    },
    "Blue": {
        "bg": "#1E1E2E",
        "fg": "white",
        "entry_bg": "#2E2E3E",
        "entry_fg": "white",
        "button_bg": "#007ACC",
        "button_fg": "white"
    },
    "Red": {
        "bg": "#3C0000",
        "fg": "white",
        "entry_bg": "#660000",
        "entry_fg": "white",
        "button_bg": "#B20000",
        "button_fg": "white"
    },
    "Green": {
        "bg": "#002E00",
        "fg": "white",
        "entry_bg": "#004F00",
        "entry_fg": "white",
        "button_bg": "#008000",
        "button_fg": "white"
    },
    "Purple": {
        "bg": "#4B0082",
        "fg": "white",
        "entry_bg": "#800080",
        "entry_fg": "white",
        "button_bg": "#BA55D3",
        "button_fg": "white"
    },
    "Orange": {
        "bg": "#FF4500",
        "fg": "white",
        "entry_bg": "#FFA500",
        "entry_fg": "white",
        "button_bg": "#FF8C00",
        "button_fg": "white"
    },
    "Yellow": {
        "bg": "#FFD700",
        "fg": "black",
        "entry_bg": "#FFFFE0",
        "entry_fg": "black",
        "button_bg": "#FFFACD",
        "button_fg": "black"
    },
    "Pink": {
        "bg": "#FF69B4",
        "fg": "white",
        "entry_bg": "#FFB6C1",
        "entry_fg": "white",
        "button_bg": "#FF1493",
        "button_fg": "white"
    },
    "Rainbow": {
        "bg": "#9400D3",
        "fg": "white",
        "entry_bg": "#4B0082",
        "entry_fg": "white",
        "button_bg": "#FF0000",
        "button_fg": "white"
    }
}

class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.current_theme = themes["Blue"]
        self.master.title("Login")
        self.master.geometry("400x250")

        self.frame = Frame(self.master, padx=20, pady=20)
        self.frame.pack(expand=True)

        self.app_name_label = Label(self.frame, text="ChitChatty v.1", font=("Helvetica", 16, "bold"))
        self.app_name_label.grid(row=0, columnspan=2, pady=10)

        self.username_label = Label(self.frame, text="Username:", font=("Helvetica", 12))
        self.username_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = Entry(self.frame, font=("Helvetica", 12), insertbackground="white")
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        self.password_label = Label(self.frame, text="Password:", font=("Helvetica", 12))
        self.password_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = Entry(self.frame, show="*", font=("Helvetica", 12), insertbackground="white")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        self.login_button = Button(self.frame, text="Login", command=self.authenticate, font=("Helvetica", 12), width=20)
        self.login_button.grid(row=3, columnspan=2, pady=10)

        self.master.bind('<Return>', lambda event: self.authenticate())

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))
        self.key = self.client_socket.recv(1024)
        self.cipher = get_cipher(self.key)

        self.username = ""

        self.apply_theme()

    def apply_theme(self):
        theme = self.current_theme
        self.master.configure(bg=theme["bg"])
        self.frame.configure(bg=theme["bg"])

        self.app_name_label.configure(bg=theme["bg"], fg=theme["fg"])
        self.username_label.configure(bg=theme["bg"], fg=theme["fg"])
        self.username_entry.configure(bg=theme["entry_bg"], fg=theme["entry_fg"])
        self.password_label.configure(bg=theme["bg"], fg=theme["fg"])
        self.password_entry.configure(bg=theme["entry_bg"], fg=theme["entry_fg"])
        self.login_button.configure(bg=theme["button_bg"], fg=theme["button_fg"])

    def authenticate(self):
        self.username = self.username_entry.get()
        password = self.password_entry.get()

        self.client_socket.send(self.username.encode())
        self.client_socket.send(password.encode())

        response = self.client_socket.recv(1024).decode()

        if response == "Authenticated":
            logging.info("Authenticated successfully")
            self.master.destroy()
            self.open_chat_window()
        else:
            logging.info("Authentication failed")
            self.username_entry.delete(0, END)
            self.password_entry.delete(0, END)
            self.username_entry.focus()

    def open_chat_window(self):
        root = Tk()
        chat_client = ChatClient(root, self.client_socket, self.cipher, self.username, self.current_theme)
        root.mainloop()

class ChatClient:
    def __init__(self, master, client_socket, cipher, username, theme):
        self.master = master
        self.master.title("Secure Chat Client")
        self.master.geometry("900x600")
        self.client_socket = client_socket
        self.cipher = cipher
        self.username = username
        self.current_theme = theme

        self.chat_frame = Frame(self.master)
        self.chat_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)

        font_emoji = tkFont.Font(family="Segoe UI Emoji", size=12)

        self.chat_text = Text(self.chat_frame, state=DISABLED, width=50, height=20, font=font_emoji)
        self.chat_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.user_text = Text(self.chat_frame, width=20, height=20, state=DISABLED, font=("Helvetica", 12))
        self.user_text.grid(row=0, column=1, padx=10, pady=10, sticky="ns")

        self.entry_text = StringVar()
        self.entry_field = Entry(self.chat_frame, textvariable=self.entry_text, font=("Helvetica", 12), insertbackground="white")
        self.entry_field.grid(row=1, column=0, padx=10, pady=5, sticky="we")

        self.entry_field.bind('<Return>', self.send_message_event)

        self.send_button = Button(self.chat_frame, text="Send", command=self.send_message, font=("Helvetica", 12), width=20)
        self.send_button.grid(row=1, column=1, padx=10, pady=5)

        self.emoji_frame = Frame(self.chat_frame, bg=theme["bg"])
        self.emoji_frame.grid(row=2, column=0, padx=10, pady=5, sticky="we", columnspan=2)

        self.chat_frame.grid_rowconfigure(0, weight=1)
        self.chat_frame.grid_columnconfigure(0, weight=1)

        self.user_text.tag_configure("vip", foreground="yellow", font=("Helvetica", 12, "bold"), justify='center')
        self.user_text.tag_configure("mod", foreground="green", font=("Helvetica", 12, "bold"), justify='center')
        self.user_text.tag_configure("admin", foreground="red", font=("Helvetica", 12, "bold"), justify='center')
        self.user_text.tag_configure("user", foreground="white", font=("Helvetica", 12), justify='center')

        self.chat_text.tag_configure("vip", foreground="yellow", font=("Segoe UI Emoji", 12, "bold"))
        self.chat_text.tag_configure("mod", foreground="green", font=("Segoe UI Emoji", 12, "bold"))
        self.chat_text.tag_configure("admin", foreground="red", font=("Segoe UI Emoji", 12, "bold"))
        self.chat_text.tag_configure("user", foreground="white", font=("Segoe UI Emoji", 12))

        self.typing_label = Label(self.chat_frame, text="", font=("Helvetica", 10), bg=theme["bg"], fg=theme["fg"])
        self.typing_label.grid(row=3, column=0, padx=10, pady=5, sticky="we", columnspan=2)

        self.ranks = {}

        self.entry_field.bind('<KeyPress>', self.typing_start_event)
        self.entry_field.bind('<KeyRelease>', self.typing_stop_event)

        self.typing_status = False

        self.thread_receive = threading.Thread(target=self.receive_messages)
        self.thread_receive.start()
        logging.info("Connected to server")

        self.menu = Menu(self.master)
        self.master.config(menu=self.menu)
        self.theme_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Themes", menu=self.theme_menu)
        for theme_name in themes:
            self.theme_menu.add_command(label=theme_name, command=lambda name=theme_name: self.change_theme(name))

        self.emoji_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Emojis", menu=self.emoji_menu)
        for emoji_name in [":thumbs_up:", ":red_heart:", ":zany_face:", ":smiling_face_with_sunglasses:", ":smiling_face_with_halo:", ":smiling_face_with_horns:", ":nauseated_face:", ":rolling_on_the_floor_laughing:", ":beaming_face_with_smiling_eyes:"]:
            self.emoji_menu.add_command(label=emoji_name, command=lambda name=emoji_name: self.insert_emoji(name))

        self.add_emoji_buttons()
        self.apply_theme()

    def apply_theme(self):
        theme = self.current_theme
        self.master.configure(bg=theme["bg"])
        self.chat_frame.configure(bg=theme["bg"])
        self.emoji_frame.configure(bg=theme["bg"])

        self.chat_text.configure(bg=theme["entry_bg"], fg=theme["entry_fg"])
        self.user_text.configure(bg=theme["entry_bg"], fg=theme["entry_fg"])
        self.entry_field.configure(bg=theme["entry_bg"], fg=theme["entry_fg"])
        self.send_button.configure(bg=theme["button_bg"], fg=theme["button_fg"])
        self.typing_label.configure(bg=theme["bg"], fg=theme["fg"])

        if self.ranks.get(self.username) == "1" and not hasattr(self, 'moderation_menu'):
            self.moderation_menu = Menu(self.menu, tearoff=0)
            self.menu.add_cascade(label="Moderation", menu=self.moderation_menu)
            self.moderation_menu.add_command(label="Clear Chat", command=self.clear_chat)
            self.moderation_menu.add_command(label="Mute User", command=self.mute_user_dialog)
            self.moderation_menu.add_command(label="Kick User", command=self.kick_user_dialog)

        for widget in self.emoji_frame.winfo_children():
            widget.configure(bg=theme["button_bg"], fg=theme["button_fg"])

    def change_theme(self, theme_name):
        self.current_theme = themes[theme_name]
        self.apply_theme()

    def insert_emoji(self, emoji_name):
        self.entry_field.insert(END, emoji.emojize(emoji_name))

    def add_emoji_buttons(self):
        emojis = ["😀", "😂", "😍", "😎", "😊", "😭", "😡", "👍", "🎉", "🤔", "😢", "🤩", "😜", "😏", "🙄", "😴", "👏", "💔", "😷"]
        for e in emojis:
            button = Button(self.emoji_frame, text=emoji.emojize(e), command=lambda e=e: self.insert_emoji(e), bg=self.current_theme["button_bg"], fg=self.current_theme["button_fg"])
            button.pack(side=LEFT, padx=2, pady=2)

    def send_message_event(self, event):
        self.send_message()
        return "break"

    def typing_start_event(self, event):
        if not self.typing_status:
            self.typing_status = True
            self.client_socket.send(encrypt_message(self.cipher, f"/typing_start {self.username}"))

    def typing_stop_event(self, event):
        if self.typing_status:
            self.typing_status = False
            self.client_socket.send(encrypt_message(self.cipher, f"/typing_stop {self.username}"))

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024)
                if message:
                    decrypted_message = decrypt_message(self.cipher, message)

                    if decrypted_message.startswith("USER_LIST:"):
                        self.update_user_list(decrypted_message[len("USER_LIST:"):])
                    elif decrypted_message.startswith("/typing_start"):
                        typing_user = decrypted_message.split()[1]
                        self.update_typing_indicator(f"{typing_user} is typing...")
                    elif decrypted_message.startswith("/typing_stop"):
                        self.update_typing_indicator("")
                    elif decrypted_message == "/clear":
                        self.chat_text.config(state=NORMAL)
                        self.chat_text.delete(1.0, END)
                        self.chat_text.config(state=DISABLED)
                    else:
                        self.display_message(decrypted_message)
                        logging.info(f"Received: {decrypted_message}")

                        if not self.master.focus_displayof():
                            notification.notify(
                                title="New Message",
                                message=decrypted_message,
                                timeout=5
                            )
                            pygame.mixer.music.load(r'C:\Users\Rares\Desktop\secure_chat\notification_sound.mp3')
                            pygame.mixer.music.play()
            except Exception as e:
                logging.error(f"Error receiving message: {e}")
                self.client_socket.close()
                break

    def update_user_list(self, user_list):
        self.user_text.config(state=NORMAL)
        self.user_text.delete(1.0, END)
        self.ranks.clear()
        for user_info in user_list.split(","):
            parts = user_info.split(":")
            if len(parts) == 3:
                user, port, rank = parts
                self.ranks[user] = rank
                tag = "user"
                if rank == "1":
                    tag = "admin"
                elif rank == "2":
                    tag = "vip"
                elif rank == "3":
                    tag = "mod"
                self.user_text.insert(END, f"{user}\n", tag)
        self.user_text.config(state=DISABLED)

        if self.ranks.get(self.username) == "1":
            if not hasattr(self, 'moderation_menu'):
                self.moderation_menu = Menu(self.menu, tearoff=0)
                self.menu.add_cascade(label="Moderation", menu=self.moderation_menu)
                self.moderation_menu.add_command(label="Clear Chat", command=self.clear_chat)
                self.moderation_menu.add_command(label="Mute User", command=self.mute_user_dialog)
                self.moderation_menu.add_command(label="Kick User", command=self.kick_user_dialog)
        else:
            if hasattr(self, 'moderation_menu'):
                self.menu.delete('Moderation')
                delattr(self, 'moderation_menu')

    def update_typing_indicator(self, typing_users):
        self.typing_label.config(text=typing_users)

    def display_message(self, message):
        try:
            user, content = message.split(": ", 1)
        except ValueError:
            logging.error(f"Malformed message received: {message}")
            return
        
        self.chat_text.config(state=NORMAL)
        rank = self.ranks.get(user, "user")
        if rank == "1":
            self.chat_text.insert(END, f"{user}: {content}\n", "admin")
        elif rank == "2":
            self.chat_text.insert(END, f"{user}: {content}\n", "vip")
        elif rank == "3":
            self.chat_text.insert(END, f"{user}: {content}\n", "mod")
        else:
            self.chat_text.insert(END, f"{user}: {content}\n", "user")
        self.chat_text.config(state=DISABLED)
        self.chat_text.see(END)

    def send_message(self):
        message = self.entry_text.get()
        if message:
            try:
                if self.client_socket:
                    encrypted_message = encrypt_message(self.cipher, message)
                    self.client_socket.send(encrypted_message)
                    self.chat_text.config(state=NORMAL)
                    self.chat_text.insert(END, f"You: {emoji.emojize(message, variant='emoji_type')}\n", "user")
                    self.chat_text.config(state=DISABLED)
                    self.chat_text.see(END)
                    self.entry_text.set("")
                    logging.info(f"Sent: {message}")
                    self.typing_stop_event(None)
                else:
                    logging.error("Client socket is not connected")
            except OSError as e:
                logging.error(f"Error sending message: {e}")

    def clear_chat(self):
        self.client_socket.send(encrypt_message(self.cipher, "/clear"))

    def mute_user_dialog(self):
        self.mute_window = Toplevel(self.master)
        self.mute_window.title("Mute User")
        self.mute_window.geometry("350x250")

        self.mute_frame = Frame(self.mute_window, padx=20, pady=20)
        self.mute_frame.pack(expand=True)

        Label(self.mute_frame, text="Username:", font=("Helvetica", 12)).pack(pady=5)
        self.mute_username_entry = Entry(self.mute_frame, font=("Helvetica", 12), insertbackground="white")
        self.mute_username_entry.pack(pady=5)

        Label(self.mute_frame, text="Duration (seconds):", font=("Helvetica", 12)).pack(pady=5)
        self.mute_duration_entry = Entry(self.mute_frame, font=("Helvetica", 12), insertbackground="white")
        self.mute_duration_entry.pack(pady=5)

        self.mute_button = Button(self.mute_frame, text="Mute", command=self.mute_user, font=("Helvetica", 12), width=15)
        self.mute_button.pack(pady=10)

        self.apply_theme_to_window(self.mute_window, self.mute_frame, self.mute_button)

    def mute_user(self):
        username = self.mute_username_entry.get()
        duration = self.mute_duration_entry.get()
        self.client_socket.send(encrypt_message(self.cipher, f"/mute {username} {duration}"))
        self.mute_window.destroy()

    def kick_user_dialog(self):
        self.kick_window = Toplevel(self.master)
        self.kick_window.title("Kick User")
        self.kick_window.geometry("300x150")

        self.kick_frame = Frame(self.kick_window, padx=20, pady=20)
        self.kick_frame.pack(expand=True)

        Label(self.kick_frame, text="Username:", font=("Helvetica", 12)).pack(pady=5)
        self.kick_username_entry = Entry(self.kick_frame, font=("Helvetica", 12), insertbackground="white")
        self.kick_username_entry.pack(pady=5)

        self.kick_button = Button(self.kick_frame, text="Kick", command=self.kick_user, font=("Helvetica", 12), width=15)
        self.kick_button.pack(pady=10)

        self.apply_theme_to_window(self.kick_window, self.kick_frame, self.kick_button)

    def kick_user(self):
        username = self.kick_username_entry.get()
        self.client_socket.send(encrypt_message(self.cipher, f"/kick {username}"))
        self.kick_window.destroy()

    def apply_theme_to_window(self, window, frame, button):
        theme = self.current_theme
        window.configure(bg=theme["bg"])
        frame.configure(bg=theme["bg"])

        for widget in frame.winfo_children():
            if isinstance(widget, Label) or isinstance(widget, Entry):
                widget.configure(bg=theme["entry_bg"], fg=theme["entry_fg"])
            if isinstance(widget, Button):
                widget.configure(bg=theme["button_bg"], fg=theme["button_fg"])

def start_client():
    root = Tk()
    login_window = LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    start_client()
