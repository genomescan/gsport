import os
from pathlib import Path

import re

from classes import MyCookieJar
from variables import GSPORT_VERSION, HOST, logged_in, frames

def login(session, username, password):
    print("[login] Opening session...")

    session.cookies = MyCookieJar(os.path.join(str(Path.home()), ".gs_cookies.txt"))
    print("[login] Get login page")
    response = session.get(HOST + "/login/")
    csrftoken = response.cookies["csrftoken"]

    first_try = True
    while re.search('name="password"', response.text) is not None or first_try:
        if not first_try:
            print("[login] Invalid credentials")
            return False
        first_try = False
        login_data = dict(
            username=username, password=password, csrfmiddlewaretoken=csrftoken, next="/"
        )
        response = session.post(
            HOST + "/login/", data=login_data, headers=dict(Referer=HOST + "/login/")
        )

    csrftoken = re.search('name="csrfmiddlewaretoken" value="(.+)"', response.text).group(1)

    return (True, response, csrftoken)