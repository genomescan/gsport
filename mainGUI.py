import os
import tkinter as tk
from pathlib import Path

from GUI.LoadingPage import LoadingPage
from GUI.ProjectPage import ProjectPage
from GUI.login import LoginPage
from GUI.MainPage import MainPage
from classes import MyCookieJar

LARGE_FONT = ("Verdana", 12)

import json
import requests
import variables
import cookies

class SeaofBTCapp(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        container = tk.Frame(self)
        self.frames = {}

        cookies.cookies = MyCookieJar(filename=os.path.join(str(Path.home()), ".gs_cookies.txt"))
        print(cookies.cookies)

        container.pack(side="top", fill="both", expand=True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        for F in (LoginPage, LoadingPage, MainPage, ProjectPage):
            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")


        self.show_frame(LoadingPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
        frame.event_generate("<<ShowFrame>>")

        if cont == LoadingPage:
            try:
                cookies.cookies.load()
                if json.loads(requests.get(variables.HOST + "/logged_in_api/", cookies=cookies.cookies).text)["logged_in"]:
                    print("Logged in")
                    self.logged_in = True
                    response = requests.get(
                        variables.HOST + "/projects",
                        cookies=cookies.cookies,
                    )
                    print(response.text)
                    #TODO: Store the projects in variables.projects variable

                    self.after(2000, self.show_frame, MainPage)
                else:
                    print("Not logged in")
                    self.after(2000, self.show_frame, LoginPage)
            except FileNotFoundError:
                print("[session] No cookies found. Logging in...")
                self.after(2000, self.show_frame, LoginPage)

# Initialize the application
app = SeaofBTCapp()
app.geometry("700x500")  # Specify window size
app.mainloop()
