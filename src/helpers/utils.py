from typing import Dict


def is_file(file: Dict) -> bool:
    """
        Check if a row entry is a file. Serves as substitute for the type field removal in the new customer portal
    :param session: Session object.
    :return: None
    """
    return file["size"] is not None


def format_size(size: str) -> str:
    """
        Format size string to have 3 digits
    :param size: Size string.
    :return: Formatted size string
    """
    size, dec = size.split(".", 1)
    while len(size) < 3:
        size = f"0{size}"
    return f"{size}.{dec}"
