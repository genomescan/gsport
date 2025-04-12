import json
import os
import time
from getpass import getpass
from multiprocessing import Queue
from pathlib import Path

import requests

from src.classes import MyCookieJar
from src.helpers.eta_readable import human_readable_eta
from src.helpers.print_functions import print_error, print_info, print_warning
from src.helpers.sizeofmetric import size_of_metric_fmt
from src.variables import (
    GSPORT_VERSION,
    HOST_URL,
    LOGGED_IN_URL,
    LOGIN_URL,
    LOGOUT_URL,
    TWO_FACTOR_AUTH_URL,
)


class Session:
    def __init__(self, options):
        self.options = options
        self.cookies = MyCookieJar(
            filename=os.path.join(str(Path.home()), ".gs_cookies.txt")
        )
        self.queue = Queue()
        self.process = Queue()

        if options.clear_cookies:
            self.logout()
        try:
            self.cookies.load()
            response = requests.get(
                options.host + LOGGED_IN_URL, cookies=self.cookies
            ).text
            if json.loads(response)["logged_in"]:
                print_info("[session] cookies found.")
            else:
                self.login()
        except FileNotFoundError:
            print_info("[session] No cookies found. Logging in...")
            self.login()

    def login(self) -> None:
        """
            This function walks the user through the login procedure, starting by making a session, followed by getting
            the csrf cookie. The user is then prompted to put in a username/email and password. They are then verified
            by the server. If successful, the server sends een login-token trough email to the user, which gsport then
            requests. After a successful authorisation, the cookie is saved.
        :return:
        """
        print_info("[login] Opening session...")
        session = requests.Session()  # Make a session.
        session.cookies = MyCookieJar(
            os.path.join(str(Path.home()), ".gs_cookies.txt")
        )  # set the cookie.
        print_info("[login] Get login page")
        # Perform a GET request to obtain the CSRF token
        response = session.get(HOST_URL + LOGIN_URL)
        csrftoken = response.cookies["csrftoken"]
        success = False
        while not success:
            username = input("Username: ")
            psw = getpass()
            login_data = dict(
                username=username, password=psw, csrfmiddlewaretoken=csrftoken, next="/"
            )
            response = session.post(
                self.options.host + LOGIN_URL,
                data=login_data,
                headers=dict(Referer=self.options.host + LOGIN_URL),
            )
            # try to log in.
            if response.status_code != 200:
                print_warning(response.text)
                continue
            login_data = dict(
                token=input("Token: "),
                password=psw,
                username=username,
                csrfmiddlewaretoken=csrftoken,
                next="/",
            )
            response = session.post(
                self.options.host + TWO_FACTOR_AUTH_URL,
                data=login_data,
                headers={
                    "Referer": self.options.host + LOGIN_URL,
                    "User-Agent": "gsport " + GSPORT_VERSION,
                },
                verify=False,
            )
            if response.status_code != 200:
                print_error(response.text)
                continue
            success = True

        print_info("[login] Success, saving cookies...")
        session.cookies.save(ignore_discard=True)

        print_info("[login] Done.")
        self.cookies = session.cookies

    def download_file(self, url: str, fsize: int, fname: str) -> None:
        """
            Download the file by streaming the dat from the url.
        :param url: The download link.
        :param fsize: The file size in bytes.
        :param fname: The filename.
        :return: None
        """
        try:
            dsize = 0
            start = time.time()

            with requests.get(
                url, stream=True, cookies=self.cookies
            ) as r:  # Start the download.
                self.options.dir = "/".join(self.options.dir.split("/")[:-1])

                if self.options.dir == "":
                    self.options.dir = ""
                with open(fname, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)

                            dsize += len(chunk)
                            rate = dsize // (time.time() - start)
                            if not self.options.download_all:
                                print(
                                    "\r"
                                    + size_of_metric_fmt(fsize)
                                    + " "
                                    + str(round(dsize / fsize * 100))
                                    + "% "
                                    + str(size_of_metric_fmt(rate))
                                    + "/sec ",
                                    "ETA:",
                                    human_readable_eta((fsize - dsize) / rate),
                                    end="     ",
                                )
                            else:
                                self.queue.put([len(chunk), False])
            if self.options.download_all:
                self.queue.put([0, True])
        except KeyboardInterrupt:
            return
        return

    def logout(self) -> None:
        try:
            self.cookies.load()
            response = requests.get(
                self.options.host + LOGOUT_URL, cookies=self.cookies
            )
            if response.status_code == 200:
                print_info("[logout] Logged out.")
            else:
                print_error("[logout] Error logging out.")
                exit(1)
            # TODO: Add code to delete cookie from system.
        except FileNotFoundError:
            print_info("[session] No cookies found to clear. exiting...")
        exit(0)
