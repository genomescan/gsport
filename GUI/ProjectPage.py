import sv_ttk
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont
import json
import requests

import variables
import cookies


def get_files(name, HOST, cookies):
    print(f"Opening project: {HOST + '/data_api_recursive/' + name}")
    response = requests.get(
        HOST + "/data_api_recursive/" + name,
        cookies=cookies,
        params={"cd": ""},
    )
    try:
        datafiles = json.loads(response.text)
        variables.projectFiles = datafiles
        return datafiles
    except json.decoder.JSONDecodeError:
        print("[get_listing] Error reading response:", response.text)
        exit(1)


project = 'test_999'


class ProjectPage(tk.Frame):

    def __init__(self, parent, container):
        tk.Frame.__init__(self, parent)
        self.bottomFrame = None
        self.topFrame = None
        self.theme = "dark"
        self.files = ""
        self.tree = None

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
                                 xscrollcommand=hsb.set,
                                 columns=("size"))
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Configure the scrollbars
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        # Configure columns
        self.tree.column("#0", width=300, minwidth=200)
        self.tree.column("size", width=100, minwidth=100, anchor=tk.E)

        # Configure headings
        self.tree.heading("#0", text="  Name", anchor=tk.W)
        self.tree.heading("size", text="Size", anchor=tk.CENTER)

        # Additional styling when using sv_ttk
        style = ttk.Style()
        if self.theme == "dark":
            self.tree.tag_configure('file', foreground='#CCCCCC')

    def display_files(self, items, parent=""):
        for item in items:
            if item["type"] == "directory":
                # Insert directory and return its ID
                folder_id = self.tree.insert(parent, 'end', text=item["name"],
                                             values=("", "Directory"),
                                             tags=('directory',))
                # Recursively add children
                if "children" in item:
                    self.display_files(item["children"], folder_id)
            else:
                # Format size
                size_bytes = item["size"]
                if size_bytes < 1024:
                    size_str = f"{size_bytes}B"
                elif size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes / 1024:.1f}KB"
                else:
                    size_str = f"{size_bytes / (1024 * 1024):.1f}MB"

                # Determine file type from extension
                file_name = item["name"]

                # Create checkbox

                # Insert file
                self.tree.insert(parent, 'end', text=file_name,
                                 values=(size_str),
                                 tags=('file',))

    def on_show_frame(self, event):
        print("Frame shown")

        # Clear the content frame to refresh the list
        for widget in self.contentFrame.winfo_children():
            widget.destroy()

        # Top frame elements
        if not self.topFrame.winfo_children():
            label = ttk.Label(self.topFrame, text=f"Project: {project}", font=self.subtitleFont)
            label.pack(pady=(5, 0), padx=10)

            description = ttk.Label(self.topFrame, text="File Explorer", font=self.textFont)
            description.pack(padx=10, pady=(0, 5))

        # Get project files
        print("Getting files...")
        self.files = get_files(variables.project, variables.HOST, cookies.cookies)

        # Create the tree view
        self.create_file_tree()

        # Display files in the tree
        if self.files and "children" in self.files:
            self.display_files(self.files["children"])

        # Expand root items
        for item in self.tree.get_children():
            self.tree.item(item, open=True)