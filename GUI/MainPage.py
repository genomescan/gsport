import sv_ttk
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont



class MainPage(tk.Frame):

    def __init__(self, parent, container):
        tk.Frame.__init__(self, parent)
        self.theme = "dark"

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
        subtitleFont = tkFont.Font(family="Segoe UI", size=22, weight="bold")
        textFont = tkFont.Font(family="Segoe UI", size=11)

        # <======== FONTS ========>
        bottomFrame = tk.Frame(self)
        bottomFrame.pack(side=tk.BOTTOM, pady=10)

        topFrame = tk.Frame(self)
        topFrame.pack()

        # <======== DISPLAYED FRAME ========>
        label = ttk.Label(topFrame, text="Welcome", font=subtitleFont)
        label.pack(pady=(10,0), padx=10)

        label = tk.Label(topFrame, text="Projects", font=textFont)
        label.pack(padx=10)

        quit_button = ttk.Button(bottomFrame, text="Quit", command=self.quit)
        quit_button.pack(side=tk.LEFT, anchor="center", padx=10)

        toggle_theme_button = ttk.Button(bottomFrame, text="Toggle Theme", command=changeTheme)
        toggle_theme_button.pack(side=tk.LEFT, anchor="center", padx=10)
