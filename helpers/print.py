from terminalcolorpy import colored, printcolor

def print_error(text: str) -> None:
    printcolor({"text": text, "color": "red"})


def print_info(text: str) -> None:
    printcolor({"text": text, "color": "cyan"})


def print_warning(text: str) -> None:
    printcolor({"text": text, "color": "yellow"})


def print_rec(dic, depth: int) -> None:
    """
        Prints the folder structure as returned from the api.
    :param dic: An iterable containing dictionaries with the keys "children", "size" and "name".
    :param depth: The recursive depth.
    :return: None
    """
    for item in dic:
        if len(item["children"]) != 0:
            for i in range(depth * 2):
                print("  ", end='')
            print("└──", colored(text=item["name"], color="cyan"))
            print_rec(item['children'], depth + 1)
        else:
            for i in range(depth * 2):
                print("  ", end='')
            print("├──", colored(text=item["name"], color="yellow"), 'Size: ',
                  colored(text=item["size"], color="red"))