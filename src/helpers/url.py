import os
from typing import Dict, List, Union

from src.helpers.parallel_download import download_parallel
from src.variables import VERIFY_FILES_URL


def get_url(session, datafiles: List[Dict[str, Union[str, int]]]) -> None:
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
            if not session.options.dir == "./" and not session.options.recursive
            else os.path.join(session.options.output, os.path.normpath(file["name"]))
        )
        filename = os.path.join(session.options.project, file["name"])
        dl_sum += fsize
        filename = filename.replace("\\", "/")
        url = session.options.host + VERIFY_FILES_URL + session.options.project
        params = {"project": session.options.project, "file": filename}
        dl_list.append([url, params, fsize, fname])

    download_parallel(session, dl_list, dl_sum)
