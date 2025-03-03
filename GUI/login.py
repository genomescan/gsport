import sv_ttk
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont
import requests

from .GUIhelpers import login, sendToken

class LoginPage(tk.Frame):
    def __init__(self, parent, container):
        tk.Frame.__init__(self, parent)
        self.log = False
        self.theme = "dark"
        self.frameManager = container

        sv_ttk.set_theme(self.theme)

        # <======== FUNCTIONS ========>
        def changeTheme():
            # Toggle between light and dark theme
            if self.theme == "dark":
                sv_ttk.set_theme("light")
                self.theme = "light"
            else:
                sv_ttk.set_theme("dark")
                self.theme = "dark"

        def Login():
            username = inputtxt.get()
            password = pwdtxt.get()
            session = requests.Session()

            (self.log , response, csrftoken) = login(session, username, password)

            if self.log:

                label = tk.Label(topFrame, text="Please input token", font=textFont)
                label.pack(pady=(20, 0), anchor='w')

                tokentxt = ttk.Entry(topFrame, width=27, font=textFont)
                tokentxt.pack(anchor='w')

                login_button.pack_forget()

                token_button = ttk.Button(self, text="Send token",command=lambda: sendToken(session, username, tokentxt.get(), response, csrftoken, self.frameManager))
                token_button.pack(pady=10)

        # <======== FONTS ========>
        subtitleFont = tkFont.Font(family="Segoe UI", size=22, weight="bold")
        textFont = tkFont.Font(family="Segoe UI", size=11)

        # <======== FRAMES ========>
        bottomFrame = tk.Frame(self)
        bottomFrame.pack(side=tk.BOTTOM, pady=10)

        topFrame = tk.Frame(self)
        topFrame.pack()

        # <======== DISPLAYED FRAMES ========>
        label = ttk.Label(topFrame, text="Log in", font=subtitleFont)
        label.pack(pady=(10,0), padx=10)

        label = tk.Label(topFrame, text="Please log in with your credentials", font=textFont)
        label.pack(padx=10)

        # <======== USERNAME ========>
        label = tk.Label(topFrame, text="Username", font=textFont)
        label.pack(pady=(20,0), anchor='w')

        inputtxt = ttk.Entry(topFrame, width=27,  font=textFont)
        inputtxt.pack(anchor='w')

        # <======== PASSWORD ========>
        label = tk.Label(topFrame, text="Password", font=textFont)
        label.pack(pady=(20, 0), anchor='w')

        pwdtxt = ttk.Entry(topFrame, width=27,font=textFont)
        pwdtxt.pack(anchor='w')

        login_button = ttk.Button(self, text="Login", command=Login)
        login_button.pack(pady=10)

        quit_button = ttk.Button(bottomFrame, text="Quit", command=self.quit)
        quit_button.pack(side=tk.LEFT, anchor="center", padx=10)

        toggle_theme_button = ttk.Button(bottomFrame, text="Toggle Theme", command=changeTheme)
        toggle_theme_button.pack(side=tk.LEFT, anchor="center", padx=10)

