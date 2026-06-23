import sys
from typing import Dict

from src.helpers.utils import is_file

if sys.version_info >= (3, 10, 0):
    from terminalcolorpy import printcolor


def print_error(text: str, end="\n") -> None:
    if sys.version_info >= (3, 10, 0):
        printcolor({"text": text, "color": "red"}, end=end)
    else:
        print(text, end=end)


def print_info(text: str, end="\n") -> None:
    if sys.version_info >= (3, 10, 0):
        printcolor({"text": text, "color": "cyan"}, end=end)
    else:
        print(text, end=end)


def print_warning(text: str, end="\n") -> None:
    if sys.version_info >= (3, 10, 0):
        printcolor({"text": text, "color": "yellow"}, end=end)
    else:
        print(text, end=end)


def print_file(text: str, end="\n") -> None:
    if sys.version_info >= (3, 10, 0):
        printcolor({"text": text, "color": "green"}, end=end)
    else:
        print(text, end=end)


def print_rec(
    data: Dict, show_md5: bool, depth: int = 0, dirs: str = "", max_depth=None
) -> None:
    """
    Prints folder structure recursively
    """
    if max_depth is not None and max_depth < depth:
        return
    for file in data:
        if not is_file(file):
            if not show_md5:
                for _ in range(depth * 2):
                    print("  ", end="")
            if not show_md5:
                if depth != 0:
                    print("└──", end="")
            if not show_md5:
                print_info(file["name"])
            print_rec(
                file["children"],
                show_md5,
                depth + 1,
                f"{dirs}{file['name']}/",
                max_depth=max_depth,
            )
        else:
            for _ in range(depth * 2):
                if not show_md5:
                    print("  ", end="")
            if show_md5:
                print(f"{file['md5']}  {dirs}{file['name']}")
            else:
                print("├──", end="")
                print_warning(file["name"], end="")
                print(" Size: ", end="")
                print_error(file["size"], end="")
                print(" Status: ", end="")
                print_error(file["file_status"])
