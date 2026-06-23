import json
import sys
from pathlib import Path
from typing import Dict

import requests

from src.classes.session import Session
from src.helpers.print_functions import (
    print_error,
    print_info,
    print_rec,
    print_warning,
)
from src.helpers.utils import is_file
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
        params={
            "cd": Path(f"{session.options.project}/{session.options.dir}").as_posix()
        },
    )
    if response.status_code == 200:
        try:
            datafiles = json.loads(response.text)
        except json.decoder.JSONDecodeError:
            print_error(f"[get_listing] Error reading response: {response.text}")
            sys.exit(1)
    elif response.status_code == 404:
        print_warning(
            "No files were found, make sure project and/or directory are correct"
        )
        sys.exit(1)
    elif response.status_code == 403:
        print_error("You are not allowed to access that project")
        sys.exit(1)
    else:
        print_error(f"[get_listing] Error reading response: {response.text}")
        sys.exit(1)
    max_depth = 0
    if session.options.dir != "./":
        datafiles["data"] = [
            find_specified_dir(datafiles["data"][0], session.options.dir)
        ]
        max_depth = 1
    if session.options.recursive:
        max_depth = None
    print_rec(datafiles["data"], session.options.show_md5, max_depth=max_depth)


def list_all_projects(session) -> None:
    """
    Prints all the projects a user has access to.
    """
    print_info("[requesting projects]")
    response = requests.get(
        session.options.host + ALL_PROJECTS_API,
        cookies=session.cookies,
    )
    try:
        projects = response.json()
        for i in projects["response"]:
            print(i)
        if response.status_code != 200:
            sys.exit(1)
    except (json.decoder.JSONDecodeError, KeyError):
        print_error(f"[get_listing] Error reading response: {response.text}")
        sys.exit(1)


def find_specified_dir(data: Dict, directory: str, depth=0):
    dir_parts = [x for x in directory.split("/") if x]
    for entry in data["children"]:
        if is_file(entry):
            continue
        if entry["name"] == dir_parts[depth]:
            if depth == len(dir_parts) - 1:
                return entry
            found_entry = find_specified_dir(entry, directory, depth + 1)
            if found_entry is not None:
                return found_entry
    return None
