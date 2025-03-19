from queue import Empty

import sv_ttk
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont
import json
import requests

import variables
import cookies

import GUI.downloads as downloads

class ProgressPage(tk.Frame):

    def __init__(self, parent, container):
        tk.Frame.__init__(self, parent)
        self.bottomFrame = None
        self.topFrame = None
        self.theme = "dark"
        self.files = ""
        self.tree = None
        self.NamesOfFilesToSend = []
        self.filesToSend = []

        sv_ttk.set_theme(self.theme)

        self.bind("<<ShowFrame>>", self.on_show_frame)

        # <======== FONTS ========>
        self.titleFont = tkFont.Font(family="Segoe UI", size=30, weight="bold")
        self.subtitleFont = tkFont.Font(family="Segoe UI", size=22, weight="bold")
        self.textFont = tkFont.Font(family="Segoe UI", size=11)

        # <======== FRAMES ========>
        self.topFrame = tk.Frame(self)
        self.topFrame.pack(fill=tk.X, pady=(10, 5))

        # Frame for the Treeview
        self.contentFrame = tk.Frame(self)
        self.contentFrame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.bottomFrame = tk.Frame(self)
        self.bottomFrame.pack(side=tk.BOTTOM, pady=10)

        def changeTheme():
            # Toggle between light and dark theme
            if self.theme == "dark":
                sv_ttk.set_theme("light")
                self.theme = "light"
            else:
                sv_ttk.set_theme("dark")
                self.theme = "dark"

        # <======== BOTTOM BUTTONS ========>
        toggle_theme_button = ttk.Button(self.bottomFrame, text="Toggle Theme", command=changeTheme)
        toggle_theme_button.pack(side=tk.LEFT, padx=5)

        go_to_main_button = ttk.Button(self.bottomFrame, text="Go to Main",
                                       command=lambda: container.show_frame("MainPage"))
        go_to_main_button.pack(side=tk.LEFT, padx=5)

        quit_button = ttk.Button(self.bottomFrame, text="Quit", command=self.quit)
        quit_button.pack(side=tk.RIGHT, padx=5)

    def on_show_frame(self, event):
        print("Frame shown")

        label = ttk.Label(self.topFrame, text=f"Current Progress", font=self.subtitleFont)
        label.pack(pady=(5, 0), padx=10)