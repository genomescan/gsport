import sv_ttk
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont
import json

import cookies
import variables
import requests

from GUI.ProjectPage import ProjectPage

def print_rec(dic, depth):
    for item in dic:
        if item["type"] == "directory":
            for i in range(depth * 2):
                print("  ", end="")
            print("└──", item["name"])
            print_rec(item["children"], depth + 1)
        else:
            for i in range(depth * 2):
                print("  ", end="")
            print("├──", item["name"], "Size: ", item["size"], "bytes")

def get_files(name, HOST, cookies):
    print(f"Opening project: {HOST + "/data_api_recursive/" + name,}")
    print("Cookies")
    print(cookies)
    response = requests.get(
        HOST + "/data_api_recursive/" + name,
        cookies=cookies,
        params={"cd": ""},
    )
    try:
        datafiles = json.loads(response.text)
        variables.projectFiles = datafiles
        print_rec(datafiles["children"], 0)
    except json.decoder.JSONDecodeError:
        print("[get_listing] Error reading response:", response.text)
        exit(1)

class MainPage(tk.Frame):

    def __init__(self, parent, container):
        tk.Frame.__init__(self, parent)
        self.theme = "dark"
        self.frameManager = container
        self.tree = None

        sv_ttk.set_theme(self.theme)

        self.bind("<<ShowFrame>>", self.on_show_frame)

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

        # <======== FRAMES ========>
        self.topFrame = tk.Frame(self)
        self.topFrame.pack(fill=tk.X, pady=(10, 5))

        # Frame for the Treeview
        self.contentFrame = tk.Frame(self)
        self.contentFrame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.bottomFrame = tk.Frame(self)
        self.bottomFrame.pack(side=tk.BOTTOM, pady=10)


        # <======== DISPLAYED FRAME ========>
        scrollbar = tk.Scrollbar(self)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        label = ttk.Label(self.topFrame, text="Welcome", font=subtitleFont)
        label.pack(pady=(10,0), padx=10)


        label = tk.Label(self.topFrame, text="Projects", font=textFont)
        label.pack(padx=10, pady=(0, 5))
        
        quit_button = ttk.Button(self.bottomFrame, text="Quit", command=self.quit)
        quit_button.pack(side=tk.LEFT, anchor="center", padx=10)

        toggle_theme_button = ttk.Button(self.bottomFrame, text="Toggle Theme", command=changeTheme)
        toggle_theme_button.pack(side=tk.LEFT, anchor="center", padx=10)

    def open_project(self, event):

        selected_index = self.tree.selection()[0]

        if selected_index:
            project_name = self.tree.item(selected_index, "text")

            variables.project = project_name

            get_files(project_name, variables.HOST, cookies.cookies)
            self.frameManager.show_frame(ProjectPage)

    def create_file_tree(self):
        # Create a frame with scrollbars for the Treeview
        tree_frame = ttk.Frame(self.contentFrame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Create vertical scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Create horizontal scrollbar
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Create Treeview
        self.tree = ttk.Treeview(tree_frame, yscrollcommand=vsb.set,
                                 xscrollcommand=hsb.set)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Configure the scrollbars
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        # Configure columns
        self.tree.column("#0", width=300, minwidth=200)

        # Configure headings
        self.tree.heading("#0", text="  Name", anchor=tk.W)

        # Additional styling when using sv_ttk
        style = ttk.Style()
        if self.theme == "dark":
            self.tree.tag_configure('file', foreground='#CCCCCC')

        self.tree.bind("<Double-Button-1>", self.open_project)

    def addFiles(self, data, parent=""):
        for file in data['projects']:
            self.tree.insert(parent, 'end', text=file)

    def on_show_frame(self, event):
        with open('projects.json', 'r') as file:
            data = json.load(file)

        # Create the file tree
        self.create_file_tree()

        # Add files to the tree
        self.addFiles(data)



        # mylist = tk.Listbox(self, yscrollcommand=scrollbar.set, bd = 0, font=textFont, height=20)
        # for i in data['projects']:
        #     mylist.insert(tk.END, i)
        #
        #
        #
        # mylist.pack(padx = 150, fill=tk.BOTH)
        # scrollbar.config(command=mylist.yview)