import sys
from typing import Dict

from src.helpers.utils import is_file

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
    for item in dic:
        if not is_file(item):
            for i in range(depth * 2):
                print("  ", end="")
            if sys.version_info >= (3, 10, 0):
                if depth == 0:
                    print(colored(text=item["name"], color="cyan"))
                else:
                    print("└──", colored(text=item["name"], color="cyan"))
            else:
                print("└── " + item["name"])
            print_rec(item["children"], depth + 1)
        else:
            for i in range(depth * 2):
                print("  ", end="")

            if sys.version_info >= (3, 10, 0):
                print(
                    "├──",
                    colored(text=item["name"], color="yellow"),
                    "Size: ",
                    colored(text=str(item["size"]), color="red"),
                )
            else:
                print(
                    "├── " + item["name"] + " Size:  " + str(item["size"]),
                )


def print_only_files(project_code: str, data: Dict):
    if project_code is not None:
        print(colored(text=project_code, color="cyan"))

    file_count = 0
    for file in data:
        if is_file(file):
            file_count += 1
            if sys.version_info >= (3, 10, 0):
                print(
                    "└──",
                    colored(text=file["name"], color="yellow"),
                    "Size: ",
                    colored(text=str(file["size"]), color="red"),
                )
            else:
                print("└──", file["name"] + " Size:  " + str(file["size"]))
    if file_count == 0:
        # TODO: Mention this somewhere else in documentation, mb remove if we do not want to print nothing
        print(
            colored(
                text="No files were found in the project root directory", color="yellow"
            )
        )


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
                        colored(text=str(file["size"]), color="red"),
                    )
                else:
                    print(file["name"])
