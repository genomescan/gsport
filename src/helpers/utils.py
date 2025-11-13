from typing import Dict


def is_file(file: Dict) -> bool:
    """
        Check if a row entry is a file. Serves as substitute for the type field removal in the new customer portal
    :param session: Session object.
    :return: None
    """
    # I we could put this insted of the function, but improves readability 
    return file["size"] != None

