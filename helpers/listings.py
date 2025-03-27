import json
import os

import requests

from .print import print_rec, print_error, print_info

from variables import PROJECT_DATA_API, ALL_PROJECTS_API

from terminalcolorpy import colored

def get_listing(session) -> None:
    """
        Gets the json in the form {data: [{name:str, size: str, children: list[dict]}]}
        and prints the values in a certain way depending on it being default, -m or -r.
    :param session: Session object.
    :return: None
    """
    response = requests.get(session.options.host + '/data_api_recursive/' +
                            session.options.project,
                            cookies=session.cookies,
                            params={"cd": session.options.dir})

    try:
        datafiles = json.loads(response.text)
    except json.decoder.JSONDecodeError:
        print_error(f"[get_listing] Error reading response: {response.text}")
        exit(1)

    if session.options.recursive:

        print_rec(datafiles["children"], 0)
    else:
        if not session.options.folder_mode:
            for file in datafiles["children"]:
                if file['type'] == "file":
                    print(colored(text=file["name"], color="yellow"), 'Size: ',
                          colored(text=str(file["size"]), color="red"))
        else:
            for file in datafiles["children"]:
                if len(file["name"]) > 0:
                    if file["type"] == "directory":
                        print(colored(text=file["name"], color="cyan"))
                    else:
                        print(colored(text=file["name"], color="yellow"))


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

def get_list(res, session_dir):
    flist = []

    def print_list(dic, path):
        for item in dic:
            if item["type"] == "directory":
                d = os.path.join(path, item["name"])
                if not os.path.isdir(d):
                    try:
                        os.makedirs(d)
                    except FileExistsError:
                        pass  # this can be the case with multithreading
                print_list(item["children"], d)
            else:
                flist.append({"name": path + "/" + item["name"], "size": item["size"]})

    print_list(json.loads(res)["children"], session_dir)
    return flist