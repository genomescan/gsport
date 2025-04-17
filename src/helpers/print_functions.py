import sys

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


def print_rec(dic, depth: int) -> None:
    """
        Prints the folder structure as returned from the api.
    :param dic: An iterable containing dictionaries with the keys "children", "size" and "name".
    :param depth: The recursive depth.
    :return: None
    """
    for item in dic:
        if item["type"] == "directory":
            for i in range(depth * 2):
                print("  ", end="")
            if sys.version_info >= (3, 10, 0):
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
