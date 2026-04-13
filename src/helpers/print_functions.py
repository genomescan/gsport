import sys
from typing import Any, Dict, List

from src.helpers.utils import format_size, is_file

if sys.version_info >= (3, 10, 0):
    from terminalcolorpy import colored, printcolor


def print_error(text: str) -> None:
    if sys.version_info >= (3, 10, 0):
        printcolor({"text": text, "color": "red"})
    else:
        print(text)


def print_info(text: str) -> None:
    if sys.version_info >= (3, 10, 0):
        printcolor({"text": text, "color": "cyan"})
    else:
        print(text)


def print_warning(text: str) -> None:
    if sys.version_info >= (3, 10, 0):
        printcolor({"text": text, "color": "yellow"})
    else:
        print(text)


def print_file(text: str) -> None:
    if sys.version_info >= (3, 10, 0):
        printcolor({"text": text, "color": "green"})
    else:
        print(text)


def print_rec(dic, depth: int = 0) -> None:
    """
        Prints the folder structure as returned from the api.
    :param dic: An iterable containing dictionaries with the keys "children", "size" and "name".
    :param depth: The recursive depth.
    :return: None
    """
    for file in dic:
        if not is_file(file):
            for i in range(depth * 2):
                print("  ", end="")
            if sys.version_info >= (3, 10, 0):
                if depth == 0:
                    print(colored(text=file["name"], color="cyan"))
                else:
                    print("└──", colored(text=file["name"], color="cyan"))
            else:
                print("└── " + file["name"])
            print_rec(file["children"], depth + 1)
        else:
            for i in range(depth * 2):
                print("  ", end="")

            if sys.version_info >= (3, 10, 0):
                print(
                    "├──",
                    colored(text=file["name"], color="yellow"),
                    "Size: ",
                    colored(text=format_size(str(file["size"])), color="red"),
                    "Status: ",
                    colored(text=str(file["file_status"]), color="red"),
                )
            else:
                print(
                    "├── "
                    + file["name"]
                    + " Size: "
                    + format_size(str(file["size"]))
                    + " Status: "
                    + str(file["file_status"]),
                )


def print_only_files(project_code: str, data: List[Dict[str, Any]]) -> None:
    if project_code is not None:
        print_info(project_code)

    file_count = 0
    for file in data:
        if is_file(file):
            file_count += 1
            if sys.version_info >= (3, 10, 0):
                print(
                    "└──",
                    colored(text=file["name"], color="yellow"),
                    "Size: ",
                    colored(text=format_size(str(file["size"])), color="red"),
                    "Status: ",
                    colored(text=str(file["file_status"]), color="red"),
                )
            else:
                print(
                    "└── "
                    + file["name"]
                    + " Size: "
                    + format_size(str(file["size"]))
                    + " Status: "
                    + str(file["file_status"])
                )
    if file_count == 0:
        print_warning("No files were found in the project root directory")


def print_folders(data: Dict) -> None:
    for file in data:
        if len(file["name"]) > 0:
            if not is_file(file):
                if sys.version_info >= (3, 10, 0):
                    print(
                        "└──" + colored(text=file["name"], color="cyan"),
                    )
                else:
                    print(file["name"])
            else:
                if sys.version_info >= (3, 10, 0):
                    print(
                        "└──",
                        colored(text=file["name"], color="yellow"),
                        "Size: ",
                        colored(text=format_size(str(file["size"])), color="red"),
                        "Status: ",
                        colored(text=str(file["file_status"]), color="red"),
                    )
                else:
                    print(
                        "└──",
                        file["name"],
                        "Size: ",
                        format_size(str(file["size"])),
                        "Status: ",
                        str(file["file_status"]),
                    )
