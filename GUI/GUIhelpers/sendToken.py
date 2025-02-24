import os
from pathlib import Path

import re

from classes import MyCookieJar
from variables import GSPORT_VERSION, HOST, logged_in, frames


def sendToken(session, username, token, response, csrftoken):

    first_try = True
    while re.search('name="csrfmiddlewaretoken" value="(.+)"', response.text) is not None or first_try:
        if not first_try:
            print("[login]", "Invalid token")
        first_try = False
        login_data = dict(token=token, username=username, csrfmiddlewaretoken=csrftoken, next="/")
        response = session.post(
            HOST + "/otp_ok/",
            data=login_data,
            headers={"Referer": HOST + "/login/", "User-Agent": "gsport " + GSPORT_VERSION},
        )

    print("[login] Success, saving cookies...")
    session.cookies.save(ignore_discard=True)

    print("[login] Done.")