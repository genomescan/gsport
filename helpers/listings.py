import json
import os

import requests

from .print_rec import print_rec
from .sizeofmetric import sizeofmetric_fmt


def get_listing(session):
    if session.options.recursive:
        response = requests.get(
            session.options.host + "/data_api_recursive/" + session.options.project,
            cookies=session.cookies,
            params={"cd": session.options.dir},
        )
        try:
            datafiles = json.loads(response.text)
            print_rec(datafiles["children"], 0)
        except json.decoder.JSONDecodeError:
            print("[get_listing] Error reading response:", response.text)
            exit(1)
    else:
        response = requests.get(
            session.options.host
            + "/data_api2/"
            + session.options.project
            + ("/y" if session.options.dirs is True else "/n"),
            cookies=session.cookies,
            params={"cd": session.options.dir},
        )
        try:
            datafiles = json.loads(response.text)
            for file in datafiles:
                if session.options.listingSize:
                    print(file["name"] + "   (" + sizeofmetric_fmt(file["size"]) + ")")
                else:
                    print(file["name"])
        except json.decoder.JSONDecodeError:
            print("[get_listing] Error reading response:", response.text)
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
