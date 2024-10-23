def center_window(window, width=300, height=150):
    # 获取屏幕宽度和高度
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # 计算窗口位置
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2

    # 设置窗口位置
    window.geometry(f'{width}x{height}+{x}+{y}')

