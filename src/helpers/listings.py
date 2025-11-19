import json
import os
import sys
from typing import Dict
import json

import requests

if sys.version_info >= (3, 10, 0):
    from terminalcolorpy import colored

from src.classes.session import Session
from src.helpers.utils import is_file
from src.helpers.print_functions import print_error, print_folders, print_only_files, print_info, print_rec
from src.variables import ALL_PROJECTS_API, LIST_RECURSIVE

def get_listing(session: Session) -> None:
    """
        Gets the json in the form {data: [{name:str, size: str, children: list[dict]}]}
        and prints the values in a certain way depending on it being default, -m or -r.
    :param session: Session object.
    :return: None
    """
    response = requests.get(
        session.options.host + LIST_RECURSIVE + session.options.project,
        cookies=session.cookies,
        params={"cd": session.options.dir},
    )
    if response.status_code == 200:
        datafiles = json.loads(response.text)
    elif response.status_code == 404:
        print(colored(text=f"No files were found for this project...", color="yellow"))
        exit(1)
    else:
        print_error(f"[get_listing] Error decoding the response")
        exit(1)
    if session.options.dir != "./":
        print_dir(datafiles["data"][0]["children"], session, session.options.dir)
        return
    if session.options.recursive:
        print_rec(datafiles["data"], 0)
    else:
        if not session.options.folder_mode:
            print_only_files(datafiles["data"][0]["children"])
            return
        else:
            print_folders(datafiles["data"][0]["children"])


def list_all_projects(session) -> None:
    """
        Prints all the projects a user has access to.
    :param session: Session object.
    :return:
    """
    print_info("[requesting projects]")
    response = requests.get(
        session.options.host + ALL_PROJECTS_API, cookies=session.cookies
    )
    try:
        projects = response.json()
        for i in projects["response"]:
            print(i)
        if response.status_code != 200:
            exit(1)
    except (json.decoder.JSONDecodeError, KeyError):
        print_error(f"[get_listing] Error reading response: {response.text}")
        exit(1)


def get_list(res, session_dir):
    flist = []

    def print_list(dic, path):
        for item in dic:
            if not is_file(item):
                d = os.path.join(path, item["name"])
                if not os.path.isdir(d):
                    try:
                        os.makedirs(d)
                    except FileExistsError:
                        pass  # this can be the case with multithreading
                print_list(item["children"], d)
            else:
                flist.append({"name":  item["name"], "size": item["size"]})

    print_list(res["data"], session_dir)
    return flist

def print_dir(data: Dict, session: Session, directory:str) -> None:
    """
        Prints the files for an specific directory.
    :param dic: An iterable containing dictionaries with the keys "children", "size" and "name".
    :param depth: The recursive depth.
    :return: None
    """
    dir_parts =[ x for x in  directory.split('/', maxsplit=1) if x]
    for file in data:
        if not is_file(file):
            if file["name"] == dir_parts[0]:
                print( colored(text=file["name"], color="cyan"),)
                if len(dir_parts) > 1:
                    print_dir(file["children"], session, dir_parts[1])
                    return
                if session.options.recursive:
                    print_rec(file["children"])
                if session.options.folder_mode:
                    print_folders(file["children"])
                else:
                    print_only_files(file["children"])
                return
            else:
                print_dir(file["children"], session, directory)
