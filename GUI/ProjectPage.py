import subprocess
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

import threading
from multiprocessing import Process, Queue
import time

from GUI.ProgressPage import ProgressPage


def download_files(self):
    # Get a reference to the progress queue
    progress_queue = downloads.download_all(None, self.filesToSend, cookies.cookies)

    # Create status display elements if needed
    if not hasattr(self, 'status_label'):
        self.status_label = ttk.Label(self.bottomFrame, text="Ready to download")
        self.status_label.pack(side=tk.LEFT, padx=5)

        self.progress_bar = ttk.Progressbar(self.bottomFrame, length=200, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, padx=5)

    # Function to check the queue periodically
    def check_progress():
        try:
            total_size = 0
            total_files = 0
            processed = 0

            # Process all available messages without blocking
            while True:
                try:
                    msg = progress_queue.get_nowait()
                    msg_type = msg[0]

                    if msg_type == "TOTAL":
                        total_size = msg[1]
                        total_files = msg[2]
                        self.progress_bar['maximum'] = total_size

                    elif msg_type == "PROGRESS":
                        chunk_size = msg[1]
                        current_size = msg[2]
                        file_size = msg[3]
                        file_name = msg[4]
                        eta = msg[5]
                        processed += chunk_size

                        # Update progress bar and status
                        if total_size > 0:
                            self.progress_bar['value'] = processed
                            percent = int(processed / total_size * 100)
                            self.status_label.config(
                                text=f"Downloading {file_name}: {percent}% - ETA: {eta}"
                            )

                    elif msg_type == "SUCCESS":
                        file_name = msg[1]
                        print(f"Successfully downloaded {file_name}")

                    elif msg_type == "MD5_FAIL":
                        file_name = msg[1]
                        print(f"MD5 check failed for {file_name}")

                    elif msg_type == "ERROR":
                        file_name = msg[1]
                        error = msg[2]
                        print(f"Error downloading {file_name}: {error}")

                    elif msg_type == "ALL_DONE":
                        self.status_label.config(text="Download complete!")
                        return  # Stop checking

                except Empty:
                    break  # No more messages to process

            # Continue checking periodically
            self.after(100, check_progress)

        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
            print(f"Error in progress check: {str(e)}")

    # Start checking for progress
    self.after(100, check_progress)

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
        self.NamesOfFilesToSend = []
        self.filesToSend = []
        self.frameManager = container

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

        Download = ttk.Button(self.bottomFrame, text="Download files", command=self.download_files)
        Download.pack(side=tk.RIGHT, padx=5)

        select_all = ttk.Button(self.bottomFrame, text="Select all", command=self.select_all)
        select_all.pack(side=tk.RIGHT, padx=5)

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

        self.tree.bind("<Button-1>", self.select_file)

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
                    size_str = f"{size_bytes} B"
                elif size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes / 1024:.1f}KB"
                else:
                    size_str = f"{size_bytes / (1024 * 1024):.1f}MB"

                # Determine file type from extension
                file_name = item["name"]

                # Insert file
                if file_name in self.NamesOfFilesToSend:
                    self.tree.insert(parent, 'end', text=file_name,
                                     values=(size_str),
                                     tags=('highlighted_file',))
                    self.tree.tag_configure('highlighted_file', foreground='#6fc276')
                else:
                    self.tree.insert(parent, 'end', text=file_name,
                                     values=(size_str),
                                     tags=('file',))

    def select_file(self, event):
        selected_index = self.tree.selection()[0]

        if not selected_index:
            return

        file_name = self.tree.item(selected_index, "text")
        size = self.tree.item(selected_index, "values")
        size = size[0][:-2]
        print(file_name)
        print(size)

        if file_name in self.NamesOfFilesToSend:
            self.NamesOfFilesToSend.remove(file_name)
            self.filesToSend.remove({"name": file_name, "size": size})
            self.on_show_frame(event)
            return

        self.NamesOfFilesToSend.append(file_name)
        self.filesToSend.append({"name": file_name, "size": int(float(size))})
        self.on_show_frame(event)

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
        print(cookies.cookies)
        self.files = get_files(variables.project, variables.HOST, cookies.cookies)

        # Create the tree view
        self.create_file_tree()

        # Display files in the tree
        if self.files and "children" in self.files:
            self.display_files(self.files["children"])

        # Expand root items
        for item in self.tree.get_children():
            self.tree.item(item, open=True)

    def select_all(self):
        for file in self.files["children"][0]['children']:
            self.NamesOfFilesToSend.append(file['name'])
            self.filesToSend.append({"name": file['name'], "size": int(float(file['size']))})

        self.on_show_frame(None)

        return

    def download_files(self):
        downloads.download_all(None, self.filesToSend, cookies.cookies)
        self.frameManager.show_frame(ProgressPage)