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

        # Set the initial theme only once when app starts
        self.theme = "dark"

        # We set the theme only once here at the start of the application
        sv_ttk.set_theme(self.theme)

        def changeTheme():
            # Toggle between light and dark theme
            if self.theme == "dark":
                sv_ttk.set_theme("light")
                self.theme = "light"
            else:
                sv_ttk.set_theme("dark")
                self.theme = "dark"

        # Custom font
        titleFont = tkFont.Font(family="Segoe UI", size=30, weight="bold")
        textFont = tkFont.Font(family="Segoe UI", size=11)

        # Create a frame for image and text
        topFrame = tk.Frame(self)
        topFrame.pack(expand=True, padx=50, anchor="w")

        textFrame = tk.Frame(topFrame)
        textFrame.pack(side=tk.RIGHT, padx=10)

        # Create bottom frame for buttons
        bottomFrame = tk.Frame(self)
        bottomFrame.pack(side=tk.BOTTOM, pady=10)

        # Load image safely
        image_path = "logo.png"
        if os.path.exists(image_path):
            img = Image.open(image_path)
            img = ImageTk.PhotoImage(img)
            # Keep a reference to the image
            self.img_ref = img  # Store the reference to prevent garbage collection
        else:
            img = None

        # Place image inside topFrame
        panel = tk.Label(topFrame, image=img) if img else tk.Label(topFrame, text="Image not found")
        panel.pack(side=tk.LEFT, fill="both")

        # Place text label inside topFrame
        label = ttk.Label(textFrame, text="Gsport", font=titleFont)
        label.pack(side=tk.TOP, anchor="w")

        # Place text label inside topFrame
        label = ttk.Label(textFrame, text="Loading ...", font=textFont)
        label.pack(side=tk.TOP, anchor="w")

        # Quit button
        quit_button = ttk.Button(bottomFrame, text="Quit", command=self.quit)
        quit_button.pack(side=tk.LEFT, anchor="center", padx=10)

        # Toggle Theme Button (Fixed)
        toggle_theme_button = ttk.Button(bottomFrame, text="Toggle Theme", command=changeTheme)
        toggle_theme_button.pack(side=tk.LEFT, anchor="center", padx=10)