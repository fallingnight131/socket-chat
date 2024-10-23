import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from windowService import center_window

ip_address = "127.0.0.1"

def receive_messages(client_socket, chat_display):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            chat_display.insert(tk.END, message + "\n")
        except:
            break


def send_message(client_socket, message_entry):
    message = message_entry.get()
    if message:
        client_socket.send(message.encode('utf-8'))
        message_entry.delete(0, tk.END)




def chat_window(client_socket, username):
    window = tk.Tk()
    window.title(f"Chat({username})")
    center_window(window, 400, 320)
    def on_closing():
        try:
            client_socket.send("<已离线>".encode('utf-8'))
        except:
            pass
        client_socket.close()
        window.destroy()
        login_window()

    # 聊天显示框
    chat_display = scrolledtext.ScrolledText(window, width=50, height=20)
    chat_display.pack()

    # 输入消息框
    message_entry = tk.Entry(window, width=40)
    message_entry.pack()

    # 创建一个Frame容器
    button_frame = tk.Frame(window)
    button_frame.pack()

    # 发送消息按钮
    send_button = tk.Button(button_frame, text="Send", command=lambda: send_message(client_socket, message_entry))
    send_button.pack(side=tk.LEFT, padx=10)

    # 返回按钮
    return_button = tk.Button(button_frame, text="Return", command=on_closing)
    return_button.pack(side=tk.LEFT, padx=5)

    # 绑定回车键发送消息
    message_entry.bind("<Return>", lambda event: send_message(client_socket, message_entry))

    # 启动接收消息的线程
    threading.Thread(target=receive_messages, args=(client_socket, chat_display)).start()

    # 捕捉窗口关闭事件
    def on_closing():
        try:
            client_socket.send("<已离线>".encode('utf-8'))
        except:
            pass
        client_socket.close()
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", on_closing)
    window.mainloop()


def start_chat(username, password, login_window):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip_address, 12345))
    client_socket.send(b"LOGIN")
    client_socket.recv(1024)  # 忽略 "Enter username" 的消息
    client_socket.send(username.encode('utf-8'))
    client_socket.recv(1024)  # 忽略 "Enter password" 的消息
    client_socket.send(password.encode('utf-8'))
    login_response = client_socket.recv(1024).decode('utf-8')
    print(login_response)
    if "successful" in login_response:
        login_window.destroy()  # 关闭登录窗口
        client_socket.send("<刚刚上线>".encode('utf-8'))
        chat_window(client_socket, username)
    elif "exit" in login_response:
        messagebox.showerror("Login Failed", "User not exit, try again.")
        print("fail, user not exit, try again.")
    elif "repeated" in login_response:
        messagebox.showerror("Login Failed", "Repeated user, try again.")
        print("fail, repeated user, try again.")
    elif "password" in login_response:
        messagebox.showerror("Login Failed", "Wrong password, try again.")
        print("wrong password, try again.")
    else:
        print("Login failed. Try again.")


def validate_and_start_chat(username_entry, password_entry, login_window):
    username = username_entry.get()
    password = password_entry.get()

    # 验证用户名和密码是否为空
    if not username or not password:
        messagebox.showerror("Input Error", "Username and password cannot be empty.")
        return

    start_chat(username, password, login_window)


def login_window():  # 创建登录窗口
    window = tk.Tk()
    window.title("Login")
    center_window(window, 300, 150)

    tk.Label(window, text="Username:").pack()
    username_entry = tk.Entry(window)
    username_entry.pack()

    tk.Label(window, text="Password:").pack()
    password_entry = tk.Entry(window, show="*")
    password_entry.pack()

    def returnStart():
        window.destroy()
        start_window()

    # 创建一个Frame容器
    button_frame = tk.Frame(window)
    button_frame.pack()

    # 在Frame中添加按钮，并使用padx参数添加空隙
    login_button = tk.Button(button_frame, text="Login",
                             command=lambda: validate_and_start_chat(username_entry, password_entry, window))
    login_button.pack(side=tk.LEFT, padx=10)

    #增加返回按钮
    return_button = tk.Button(button_frame, text="Return", command=returnStart)
    return_button.pack(side=tk.LEFT, padx=5)

    window.mainloop()


def register_window():
    window = tk.Tk()
    window.title("Register")
    center_window(window, 300, 150)

    tk.Label(window, text="Username:").pack()
    username_entry = tk.Entry(window)
    username_entry.pack()

    tk.Label(window, text="Password:").pack()
    password_entry = tk.Entry(window, show="*")
    password_entry.pack()

    def register():
        username = username_entry.get()
        password = password_entry.get()
        if not username or not password:
            messagebox.showerror("Input Error", "Username and password cannot be empty.")
            return
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip_address, 12345))
            client_socket.send(b"REGISTER")  # 发送Command
            client_socket.recv(1024)  # 忽略 "Enter username" 的消息
            client_socket.send(username.encode('utf-8'))
            client_socket.recv(1024)  # 忽略 "Enter password" 的消息
            client_socket.send(password.encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8')
            if "successful" in response:
                messagebox.showinfo("Success", "Registration successful!")
                window.destroy()
                start_window()
            else:
                messagebox.showerror("Error", response)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            client_socket.close()

    def returnStart():
        window.destroy()
        start_window()

    # 创建一个Frame容器
    button_frame = tk.Frame(window)
    button_frame.pack()

    # 在Frame中添加按钮
    register_button = tk.Button(button_frame, text="Register", command=register)
    register_button.pack(side=tk.LEFT, padx=10)

    #增加返回按钮
    return_button = tk.Button(button_frame, text="Return", command=returnStart)
    return_button.pack(side=tk.LEFT, padx=5)

    window.mainloop()


def delete_account_window():
    window = tk.Tk()
    window.title("Delete Account")
    center_window(window, 300, 150)

    tk.Label(window, text="Username:").pack()
    username_entry = tk.Entry(window)
    username_entry.pack()

    tk.Label(window, text="Password:").pack()
    password_entry = tk.Entry(window, show="*")
    password_entry.pack()

    def delete_account():
        global client_socket
        username = username_entry.get()
        password = password_entry.get()
        if not username:
            messagebox.showerror("Input Error", "Username cannot be empty.")
            return
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip_address, 12345))
            client_socket.send(b"DELETE")
            client_socket.recv(1024)  # 忽略 "Enter username" 的消息
            client_socket.send(username.encode('utf-8'))
            client_socket.recv(1024)  # 忽略 "Enter password" 的消息
            client_socket.send(password.encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8')
            if "successful" in response:
                messagebox.showinfo("Success", "Account deleted successfully!")
                window.destroy()
                start_window()
            else:
                messagebox.showerror("Error", response)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            client_socket.close()

    def returnStart():
        window.destroy()
        start_window()

    # 创建一个Frame容器
    button_frame = tk.Frame(window)
    button_frame.pack()

    # 在Frame中添加按钮
    delete_button = tk.Button(button_frame, text="Delete Account", command=delete_account)
    delete_button.pack(side=tk.LEFT, padx=10)

    #增加返回按钮
    return_button = tk.Button(button_frame, text="Return", command=returnStart)
    return_button.pack(side=tk.LEFT, padx=5)


def start_window():
    window = tk.Tk()
    window.title("Start")
    center_window(window, 300, 120)

    def login_command():
        window.destroy()
        login_window()

    def register_command():
        window.destroy()
        register_window()

    def delete_command():
        window.destroy()
        delete_account_window()

    login_button = tk.Button(window, text="Login", command=login_command)
    login_button.pack()

    register_button = tk.Button(window, text="Register", command=register_command)
    register_button.pack()

    delete_button = tk.Button(window, text="Delete Account", command=delete_command)
    delete_button.pack()

    window.mainloop()


if __name__ == "__main__":
    start_window()
