from variables import DOWNLOAD_FILE_URL
from .parallel_download import download_parallel_linux
import os

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
        fsize = file['size'] if file['size'] != 0 else 1
        fname = os.path.join(session.options.output, file['name'].replace("\\", "/").split("/")[-1]) if not session.options.recursive else os.path.join(session.options.output, os.path.normpath(file["name"]))
        dl_sum += fsize
        url = (session.options.host + DOWNLOAD_FILE_URL + session.options.project, {"file": file['name']})
        print(url)
        dl_list.append([url, fsize, fname])

    download_parallel_linux(session, dl_list, dl_sum)