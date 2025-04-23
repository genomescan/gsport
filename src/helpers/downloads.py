import os
from typing import Dict, List, Union

import requests

from src.variables import DOWNLOAD_FILE_URL, DOWNLOAD_RECURSIVE

from .listings import get_list
from .print_functions import print_error, print_warning
from .url import get_url


def download(session) -> None:
    """
        Verify the files specified with the download command and passes the approved files to the get url.
    :param session: The session object.
    :return: None
    """
    datafiles = ""
    if session.options.download:
        response = requests.get(
            session.options.host + DOWNLOAD_FILE_URL + session.options.project + "/n",
            cookies=session.cookies,
            params={"cd": session.options.dir},
        )
        datafiles = response
        print(datafiles)
        print(
            session.options.host + DOWNLOAD_FILE_URL + session.options.project + "/y",
        )

        print(session.options.dir)
        datafiles = datafiles["children"]
    elif session.options.download_all and session.options.recursive:
        response = requests.get(
            session.options.host + DOWNLOAD_RECURSIVE + session.options.project,
            cookies=session.cookies,
            params={"cd": session.options.dir},
        )
        datafiles = get_list(response.text, session.options.dir)
    elif session.options.download_all:
        response = requests.get(
            session.options.host + DOWNLOAD_FILE_URL + session.options.project + "/n",
            cookies=session.cookies,
            params={"cd": session.options.dir},
        )
        datafiles = response.json()
    else:
        exit(1)

    if response.status_code != 200:
        print_error(response.text)
        exit(1)

    if session.options.download:
        if len(datafiles) < len(session.options.download):
            requested = set(session.options.download)
            allowed = {i["name"] for i in datafiles}
            not_allowed = requested - allowed
            for i in not_allowed:
                print_warning(
                    f"WARNING: {i} is not a valid file for download, make sure the path is spelled correctly."
                )
            if input("Continuing on with download of valid files? (y/n)") != "y":
                exit(1)
    if not os.path.isdir(
        session.options.output
    ):  # Create the output folder if it doesn't exist.
        os.makedirs(session.options.output)
    if session.options.download_all and session.options.recursive:
        make_directories(datafiles, output=session.options.output)
    get_url(session, datafiles)


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
