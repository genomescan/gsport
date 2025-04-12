import os

import requests

from src.variables import VERIFY_FILES_URL

from .parallel_download import download_parallel


def get_url(session, datafiles: list[dict[str, str | int]]) -> None:
    """
        Generate the url of every file to be downloaded and puts them in a list. Call the multithreading download function
        if the os is Linux, otherwise call the download function for each file to be downloaded.
    :param session: Session object.
    :param datafiles: The list of dictionaries representing files with a size in bytes and name: as path.
    :return: None
    """
    dl_list = []
    dl_sum = 0

    for file in datafiles:
        fsize = file["size"] if file["size"] != 0 else 1
        fname = (
            os.path.join(
                session.options.output, file["name"].replace("\\", "/").split("/")[-1]
            )
            if not session.options.recursive
            else os.path.join(session.options.output, os.path.normpath(file["name"]))
        )
        filename = (
            "/"
            + (session.options.dir if not session.options.recursive else "")
            + "/"
            + file["name"]
        )
        dl_sum += fsize
        response = requests.get(
            session.options.host + VERIFY_FILES_URL,
            cookies=session.cookies,
            params={"project": session.options.project, "filename": filename},
        )
        url = (
            session.options.host
            + "/session_files2/"
            + session.options.project
            + "/"
            + response.text
        )
        dl_list.append([url, fsize, fname])

    download_parallel(session, dl_list, dl_sum)
