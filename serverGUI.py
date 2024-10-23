import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import csv
from windowService import center_window

def load_user_db(file_path):
    user_db = {}
    try:
        with open(file_path, mode='r', newline='') as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) == 2:

                    username, password = row
                    user_db[username] = password
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return user_db

def save_user_db(user_db, file_path):
    try:
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            for username, password in user_db.items():
                writer.writerow([username, password])
    except Exception as e:
        print(f"An error occurred: {e}")


# 假设我们有一个简单的用户数据库，用户名:密码
user_db = {}

clients = {}
clients_lock = threading.Lock()
server_socket = None
server_running = False

# 广播消息给所有连接的客户端
def broadcast(message, client_socket):
    sender = ''
    for client in clients:
        if clients[client] == client_socket:
            sender = client

    for client in clients:
        if client != sender:
            try:
                head = f'({sender})'
                head = head.encode('utf-8')
                messageFinal = head + message
                clients[client].send(messageFinal)
            except:
                pass
        else:
            try:
                head = f'(you)'
                head = head.encode('utf-8')
                messageFinal = head + message
                clients[client].send(messageFinal)
            except:
                pass

# 处理每个客户端的通信
def handle_client(client_socket, address):
    global clients
    global user_db
    user_db = load_user_db('datas/users.csv')
    username = None  # 初始化用户名变量

    try:
        while server_running:
            try:
                valid = False
                command = client_socket.recv(1024).decode('utf-8').strip()      # 接收客户端的命令
                if command == "REGISTER":
                    client_socket.send(b"Enter username: ")
                    username = client_socket.recv(1024).decode('utf-8').strip()
                    client_socket.send(b"Enter password: ")
                    password = client_socket.recv(1024).decode('utf-8').strip()
                    with clients_lock:
                        if username in user_db:
                            client_socket.send(b"fail, user already exists.\n")
                        else:
                            user_db[username] = password
                            client_socket.send(b"Registration successful!\n")
                    return
                elif command == "DELETE":
                    client_socket.send(b"Enter username: ")
                    username = client_socket.recv(1024).decode('utf-8').strip()
                    client_socket.send(b"Enter password: ")
                    password = client_socket.recv(1024).decode('utf-8').strip()
                    with clients_lock:
                        if username in user_db and user_db[username] == password:
                            del user_db[username]
                            client_socket.send(b"Account deletion successful!\n")
                        elif username not in user_db:
                            client_socket.send(b"fail, user does not exist.\n")
                        else:
                            client_socket.send(b"fail, wrong password.\n")
                    return
                else:
                    client_socket.send(b"Enter username: ")
                    username = client_socket.recv(1024).decode('utf-8').strip()
                    client_socket.send(b"Enter password: ")
                    password = client_socket.recv(1024).decode('utf-8').strip()

                    with clients_lock:
                        if username in user_db and username not in clients and user_db[username] == password:
                            client_socket.send(b"Login successful!\n")
                            clients[username] = client_socket
                            valid = True
                            break
                        elif username not in user_db:
                            client_socket.send(b"fail, user not exit, try again.\n")
                            valid = False
                            continue
                        elif username in clients:
                            client_socket.send(b"fail, repeated user, try again.\n")
                            valid = False
                            continue
                        elif user_db[username] != password:
                            client_socket.send(b"wrong password, try again.\n")
                            valid = False
                            continue

            except ConnectionResetError:
                server_log.insert(tk.END, f"Connection reset by {address}\n")
                client_socket.close()
                return

        # 接受并转发客户端消息
        server_log.insert(tk.END, f"Client {username} connected from {address}\n")
        while server_running:
            try:
                message = client_socket.recv(1024)
                if message:
                    broadcast(message, client_socket)
                else:
                    raise Exception("Client disconnected")
            except ConnectionResetError:
                server_log.insert(tk.END, f"Connection reset by {address}\n")
                client_socket.close()
                break
            except ConnectionAbortedError:
                server_log.insert(tk.END, f"Connection aborted by {address}\n")
                client_socket.close()
                break
            except:
                client_socket.close()
                server_log.insert(tk.END, f"Client {username} disconnected\n")
                break
    except ConnectionAbortedError:
        server_log.insert(tk.END, f"Connection aborted by {address}\n")
        client_socket.close()
    finally:
        with clients_lock:
            if valid and username in clients:
                del clients[username]
        client_socket.close()
        save_user_db(user_db, 'datas/users.csv')
def start_server():
    global server_socket, server_running
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 允许端口重用
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)
    server_socket.settimeout(1)  # Set the server timeout to 1 second
    server_running = True

    server_log.insert(tk.END, "Server started on port 12345\n")

    try:
        while server_running:
            try:
                client_socket, address = server_socket.accept()
                server_log.insert(tk.END, f"Connection from {address}\n")
                threading.Thread(target=handle_client, args=(client_socket, address)).start()
            except socket.timeout:
                continue
            except OSError as e:
                server_log.insert(tk.END, f"Server error: {e}\n")
                break
    except KeyboardInterrupt:
        server_log.insert(tk.END, "Server shutting down...\n")
    finally:
        server_socket.close()

def stop_server():
    global server_running
    server_running = False
    server_log.insert(tk.END, "Server stopped.\n")
    with clients_lock:
        for client_socket in clients.values():
            client_socket.close()
        clients.clear()

# GUI 界面
def start_gui():
    global server_log
    window = tk.Tk()
    window.title("TCP Server")
    center_window(window, 400, 330)
    # 日志显示框
    server_log = scrolledtext.ScrolledText(window, width=50, height=20)
    server_log.pack()

    # 启动服务器按钮
    start_button = tk.Button(window, text="Start Server", command=lambda: threading.Thread(target=start_server).start())
    start_button.pack()

    # 关闭服务器按钮
    stop_button = tk.Button(window, text="Stop Server", command=stop_server)
    stop_button.pack()

    try:
        window.mainloop()
    except KeyboardInterrupt:
        print("Program interrupted by user.")

if __name__ == "__main__":
    start_gui()