import os
from typing import Dict, List, Optional, Union

import requests

from src.classes.session import Session
from src.helpers.print_functions import print_error, print_file, print_warning
from src.helpers.url import get_url
from src.helpers.utils import is_file
from src.variables import DOWNLOAD_FILE_URL


def _get_file_names(files: List[Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    file_names = {}
    for file in files:
        file_names[file["name"]] = file
    return file_names


def _normalize_dir(session: Session) -> None:
    """Prepend the project name to the directory path if it isn't already included."""
    if (
        session.options.dir.split("/")[0] != session.options.project
        and session.options.dir != "./"
    ):
        session.options.dir = session.options.project + "/" + session.options.dir


def _fetch_datafiles(session: Session) -> Optional[requests.Response]:
    """
    Perform the appropriate API request based on the session download options.

    Returns the response object, or None if no valid download option was set.
    """
    base_url = session.options.host + DOWNLOAD_FILE_URL + session.options.project
    params = {"cd": session.options.dir}
    kwargs = {"cookies": session.cookies, "params": params}

    if session.options.download or (
        session.options.download_all and session.options.recursive
    ):
        return requests.get(base_url + "/recursive", **kwargs)
    elif session.options.download_all:
        return requests.get(base_url + "/dirs", **kwargs)

    return None


def download(session: Session) -> None:
    """
        Verify the files specified with the download command and passes the approved files to the get url.
    :param session: The session object.
    :return: None
    """
    _normalize_dir(session)

    response = _fetch_datafiles(session)
    if response is None:
        exit(1)

    if response.status_code != 200:
        print_error(response.text)
        exit(1)
    datafiles = _list_files(response.json(), session.options.output)
    if session.options.download:
        requested = session.options.download
        allowed = _get_file_names(datafiles)

        datafiles = []
        for file in requested:
            file = f"{session.options.project}/{file}"
            if file not in allowed:
                print_warning(
                    f"WARNING: {file} is not a valid file for download or it has expired, make sure the path is spelled correctly."
                )
                continue
            if file in allowed:
                print_file(file)
                datafiles.append(allowed[file])
        if not len(datafiles) > 0:
            print("No valid files to download")
            exit(1)
        if input("Continuing on with the download of the existing files? (y/n)") != "y":
            exit(1)

    if not os.path.isdir(
        session.options.output
    ):  # Create the output folder if it doesn't exist.
        os.makedirs(session.options.output)
    # Make sure directories exist
    datafiles = simplify_path(datafiles)
    if session.options.download_all and session.options.recursive:
        make_directories(datafiles, output=session.options.output)
    get_url(session, datafiles)


def _list_files(res, session_dir):
    flist = []

    def recursive_list(dic, path):
        for item in dic:
            if not is_file(item):
                d = os.path.join(path, item["name"])
                if not os.path.isdir(d):
                    try:
                        os.makedirs(d)
                    except FileExistsError:
                        pass  # this can be the case with multithreading
                recursive_list(item["children"], d)
            else:
                flist.append({"name": item["name"], "size": item["size"]})

    recursive_list(res["data"], session_dir)
    return flist


def simplify_path(
    datafiles: List[Dict[str, Union[str, int]]],
) -> List[Dict[str, Union[str, int]]]:
    """Remove a leading project directory from file paths while preserving already-relative names."""
    for file in datafiles:
        name = str(file["name"])
        path = name.split("/")
        if len(path) > 1:
            subdirectories = path[1:]
            if subdirectories:
                file["name"] = "/".join(subdirectories)
        else:
            file["name"] = name
    return datafiles


def make_directories(
    files: List[Dict[str, Union[str, int]]],
    directory_path_length: int = 0,
    output: str = ".",
) -> None:
    """
        Create the directories that the files will be put in.
    :param files: The list of dictionaries containing file information.
    :param directory_path_length:
    :param output: The output directory.
    :return: None
    """
    for file in files:  # Go through every file.
        total_path = output  # Begin the path with the output directory.
        for path in file["name"].split("/")[
            directory_path_length:-1
        ]:  # Loop through the elements of the path, but not the file. This works because the server should never return "\" based paths.
            total_path = os.path.join(
                total_path, path
            )  # Append the path element to the total path.
            if not os.path.isdir(
                total_path
            ):  # Create the directory with the using the total path if it doesn't exist yet.
                try:
                    os.makedirs(total_path)
                except FileExistsError:
                    pass  # This can be the case with multithreading.
