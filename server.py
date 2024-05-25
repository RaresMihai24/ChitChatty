import socket
import threading
import logging
from encryption import generate_key, get_cipher, encrypt_message, decrypt_message
import time

HOST = '127.0.0.1'
PORT = 12345

logging.basicConfig(filename=r'C:\Users\Rares\Desktop\secure_chat\logs.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

key = generate_key()
cipher = get_cipher(key)

clients = []
client_usernames = {}
muted_users = {}  

def load_users():
    users = {}
    with open(r'C:\Users\Rares\Desktop\secure_chat\users.txt', 'r') as file:
        for line in file:
            username, password, rank = line.strip().split(':')
            users[username] = (password, rank)  
    return users

users = load_users()

def handle_client(client_socket, addr):
    logging.info(f"New connection from {addr}")

    authenticated = False
    username = ""
    while not authenticated:
        username = client_socket.recv(1024).decode()
        password = client_socket.recv(1024).decode()
        
        if username in users and users[username][0] == password:
            authenticated = True
            client_socket.send("Authenticated".encode())
            logging.info(f"User {username} authenticated from {addr}")
            client_usernames[client_socket] = username
            update_user_list()
        else:
            client_socket.send("Authentication failed".encode())
            logging.info(f"User {username} failed to authenticate from {addr}")

    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                decrypted_message = decrypt_message(cipher, message)
                if username in muted_users and muted_users[username] > time.time():
                    client_socket.send(encrypt_message(cipher, "You are muted."))
                    continue

                logging.info(f"Received from {addr}: {decrypted_message}")
                
                if decrypted_message.startswith("/"):
                    handle_command(decrypted_message, username, client_socket)
                else:
                    broadcast_message(f"{username}: {decrypted_message}", client_socket)
            else:
                remove_client(client_socket, addr)
                break
        except Exception as e:
            logging.error(f"Error with client {addr}: {e}")
            remove_client(client_socket, addr)
            break

def handle_command(command, username, client_socket):
    parts = command.split()
    cmd = parts[0].lower()

    if cmd == "/clear" and users[username][1] == "1":
        broadcast_message("The chat has been cleared by an admin.", None)
        for client in clients:
            client.send(encrypt_message(cipher, "/clear"))

    elif cmd == "/mute" and users[username][1] == "1":
        if len(parts) == 3:
            user_to_mute = parts[1]
            mute_time = int(parts[2])
            if user_to_mute in [client_usernames[c] for c in clients]:
                muted_users[user_to_mute] = time.time() + mute_time
                broadcast_message(f"{user_to_mute} has been muted for {mute_time} seconds by an admin.", None)

    elif cmd == "/kick" and users[username][1] == "1":
        if len(parts) == 2:
            user_to_kick = parts[1]
            for client in clients:
                if client_usernames[client] == user_to_kick:
                    client.send(encrypt_message(cipher, "You have been kicked by an admin."))
                    remove_client(client)
                    broadcast_message(f"{user_to_kick} has been kicked by an admin.", None)
                    break

def broadcast_message(message, current_client):
    encrypted_message = encrypt_message(cipher, message)
    for client in clients:
        if client != current_client:
            try:
                client.send(encrypted_message)
            except:
                remove_client(client)

def update_user_list():
    user_list = []
    for client_socket, username in client_usernames.items():
        rank = users[username][1]  
        user_list.append(f"{username}:1234:{rank}") 
    user_list_str = ",".join(user_list)
    encrypted_user_list = encrypt_message(cipher, f"USER_LIST:{user_list_str}")
    for client in clients:
        try:
            client.send(encrypted_user_list)
        except Exception as e:
            logging.error(f"Error sending user list to client: {e}")
            remove_client(client)

def remove_client(client_socket, addr=None):
    if client_socket in clients:
        clients.remove(client_socket)
        username = client_usernames.pop(client_socket, "Unknown")
        if addr:
            logging.info(f"Connection with {addr} closed ({username})")
        update_user_list()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    logging.info(f"Server started and listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        clients.append(client_socket)
        client_socket.send(key)
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
