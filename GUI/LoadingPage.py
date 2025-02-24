import time

import sv_ttk
import tkinter as tk
from tkinter import ttk
from PIL import ImageTk, Image
import tkinter.font as tkFont
import os


class LoadingPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.theme = "dark"
        self.img_ref = ""

        sv_ttk.set_theme(self.theme)

        def changeTheme():
            # Toggle between light and dark theme
            if self.theme == "dark":
                sv_ttk.set_theme("light")
                self.theme = "light"
            else:
                sv_ttk.set_theme("dark")
                self.theme = "dark"

        # <======== FONTS ========>
        titleFont = tkFont.Font(family="Segoe UI", size=30, weight="bold")
        textFont = tkFont.Font(family="Segoe UI", size=11)

        # <======== FRAMES ========>
        topFrame = tk.Frame(self)
        topFrame.pack(expand=True, padx=50, anchor="w")

        textFrame = tk.Frame(topFrame)
        textFrame.pack(side=tk.RIGHT, padx=10)

        bottomFrame = tk.Frame(self)
        bottomFrame.pack(side=tk.BOTTOM, pady=10)

        # <======== DISPLAYED FRAME ========>
        image_path = "GUI/logo.png"
        if os.path.exists(image_path):
            img = Image.open(image_path)
            img = ImageTk.PhotoImage(img)

            self.img_ref = img
        else:
            img = None

        panel = tk.Label(topFrame, image=img) if img else tk.Label(topFrame, text="Image not found")
        panel.pack(side=tk.LEFT, fill="both")

        label = ttk.Label(textFrame, text="Gsport", font=titleFont)
        label.pack(side=tk.TOP, anchor="w")

        label = ttk.Label(textFrame, text="Loading ...", font=textFont)
        label.pack(side=tk.TOP, anchor="w")

        quit_button = ttk.Button(bottomFrame, text="Quit", command=self.quit)
        quit_button.pack(side=tk.LEFT, anchor="center", padx=10)

        toggle_theme_button = ttk.Button(bottomFrame, text="Toggle Theme", command=changeTheme)
        toggle_theme_button.pack(side=tk.LEFT, anchor="center", padx=10)