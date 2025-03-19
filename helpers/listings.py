import json
import os

import requests

from helpers import print_rec, print_error, print_info
from variables import PROJECT_DATA_API

from terminalcolorpy import colored

def get_listing(session) -> None:
    """
        Gets the json in the form {data: [{name:str, size: str, children: list[dict]}]}
        and prints the values in a certain way depending on it being default, -m or -r.
    :param session: Session object.
    :return: None
    """
    response = requests.get(session.options.host + PROJECT_DATA_API + session.options.project,
                            params={"dirs": session.options.dir},
                            cookies=session.cookies, verify=False)
    try:
        datafiles = json.loads(response.text)
    except json.decoder.JSONDecodeError:
        print_error(f"[get_listing] Error reading response: {response.text}")
        exit(1)
    if session.options.recursive:
        print_rec(datafiles["data"], 0)
    else:
        if not session.options.folder_mode:
            for file in datafiles["data"]:
                if len(file["children"]) == 0:
                    print(colored(text=file["name"], color="yellow"), 'Size: ',
                          colored(text=file["size"], color="red"))
        else:
            for file in datafiles["data"]:
                if len(file["children"]) > 0:
                    print(colored(text=file["name"], color="cyan"))


def list_all_projects(session) -> None:
    """
        Prints all the projects a user has access to.
    :param session: Session object.
    :return:
    """
    print_info("[requesting projects]")
    response = requests.get(session.options.host + ALL_PROJECTS_API,
                            cookies=session.cookies, verify=False)
    try:
        projects = response.json()
        for i in projects["response"]:
            print(i)
        if response.status_code != 200:
            exit(1)
    except (json.decoder.JSONDecodeError, KeyError):
        print_error(f"[get_listing] Error reading response: {response.text}")
        exit(1)
