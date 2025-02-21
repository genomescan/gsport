import time
import sv_ttk
import tkinter as tk
from tkinter import ttk
from PIL import ImageTk, Image
import tkinter.font as tkFont
import os

class LoginPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.theme = "dark"

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

        # Create bottom frame for buttons
        bottomFrame = tk.Frame(self)
        bottomFrame.pack(side=tk.BOTTOM, pady=10)

        # Create a frame for image and text
        topFrame = tk.Frame(self)
        topFrame.pack()

        titleFont = tkFont.Font(family="Segoe UI", size=30, weight="bold")
        subtitleFont = tkFont.Font(family="Segoe UI", size=22, weight="bold")
        textFont = tkFont.Font(family="Segoe UI", size=11)

        label = ttk.Label(topFrame, text="Log in", font=subtitleFont)
        label.pack(pady=(10,0), padx=10)

        label = tk.Label(topFrame, text="Please log in with your credentials", font=textFont)
        label.pack(padx=10)


        # Username textbox
        label = tk.Label(topFrame, text="Username", font=textFont)
        label.pack(pady=(20,0), anchor='w')

        inputtxt = ttk.Entry(topFrame, width=27,  font=textFont)
        inputtxt.pack(anchor='w')
        # End username textbox

        # Password textbox
        label = tk.Label(topFrame, text="Password", font=textFont)
        label.pack(pady=(20, 0), anchor='w')

        pwdtxt = ttk.Entry(topFrame, width=27,font=textFont)
        pwdtxt.pack(anchor='w')
        # End Password textbox

        # Button to print input
        print_button = ttk.Button(self, text="Login", command=Login)
        print_button.pack(pady=10)

        # Toggle Theme Button (Fixed)
        toggle_theme_button = ttk.Button(bottomFrame, text="Toggle Theme", command=changeTheme)
        toggle_theme_button.pack(side=tk.LEFT, anchor="center", padx=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginPage(root, None)
    app.pack(fill="both", expand=True)
    root.geometry("400x300")
    sv_ttk.set_theme("dark")
    root.mainloop()
