"""
GSPORT command-line tool for accessing GenomeScan Customer Portal
---
(C) GenomeScan B.V. 2019
N.J. de Water - Software Developer
"""

from getpass import getpass
from multiprocessing import Process, Pool, Queue
import http.cookiejar
import requests
import getopt
import sys
import re
import json
import time
import platform


def usage():
    print("""
Usage: gsport [options]
GSPORT command-line tool for accessing GenomeScan Customer Portal

Options
-h --host [host], default: https://portal.genomescan.nl
-p --project [project] project (required with -l, -d, -a)
-l --list list
-d --download [filename] download
-a --download-all download all files from project -p or --project
-c --clear-cookies clear session/cookies
-H --help prints this help
""")


def human_readable_eta(seconds):
    days = seconds // 86400
    hours = seconds // 3600 % 24
    minutes = seconds // 60 % 60
    seconds = seconds % 60
    ret = str(round(days))+'d' if days > 0 else ''
    ret += str(round(hours))+'h' if hours > 0 else ''
    ret += str(round(minutes))+'m' if minutes > 0 else ''
    ret += str(round(seconds))+'s' if seconds > 0 and minutes < 1 else ''
    return ret


def sizeofmetric_fmt(num, suffix='B'):
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1000.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1000.0
    return "%.1f %s%s" % (num, 'Y', suffix)


class Options:
    def __init__(self, argv):
        self.download = None
        self.download_all = False
        self.host = "https://portal.genomescan.nl/"
        self.listing = False
        self.help = False
        self.project = None
        self.no_options = True
        self.found_project = False
        self.clear_cookies = False
        self.threads = 1

        try:
            opts, args = getopt.getopt(argv[1:],
                                       "h:p:ld:acHt:",
                                       ["host=", "project=", "list",
                                        "download=", "download-all", "threads"
                                        "clear-cookies", "help"])

        except getopt.GetoptError as err:
            print(err)
            usage()
            exit(1)

        for o, a in opts:
            if o in ("-H", "--help"):
                usage()
                exit()
            elif o in ("-h", "--host"):
                self.host = a
            elif o in ("-p", "--project"):
                self.project = a
                self.found_project = True
            elif o in ("-l", "--list"):
                self.listing = True
                self.no_options = False
            elif o in ("-d", "--download"):
                self.download = a
                self.no_options = False
            elif o in ("-t", "--threads"):
                self.threads = a
            elif o in ("-a", "--download-all"):
                self.download_all = True
                self.no_options = False
            elif o in ("-c", "--clear-cookies"):
                self.clear_cookies = True
                self.no_options = False
            else:
                assert False
        if (self.listing or self.download or self.download_all) and not self.found_project:
            print("[error] listing, download and download all require a project")
            usage()
            exit(1)
        if self.found_project and self.no_options:
            print("[error] project with no other option, what do you want?")
            usage()
            exit(1)
        if self.download is not None and self.download_all:
            print("[error] cannot download one file and all files (option -d and -a)")
            usage()
            exit(1)
        if not self.download_all:
            self.threads = 1


class Session:
    def __init__(self, options):
        self.options = options
        self.cookies = http.cookiejar.MozillaCookieJar(filename='gs_cookies.txt')
        self.logged_in = False
        self.queue = Queue()
        self.process = Queue()

        try:
            self.cookies.load()
            if json.loads(requests.get(options.host + '/logged_in_api/', cookies=self.cookies).text)['logged_in']:
                self.logged_in = True
            else:
                self.login()
        except FileNotFoundError:
            print("[session] No cookies found. Logging in...")
            self.login()

    def login(self):
        print("[login] Opening session...")
        session = requests.Session()
        session.cookies = http.cookiejar.MozillaCookieJar('gs_cookies.txt')
        print("[login] Get login page")
        response = session.get(self.options.host + "/login/")
        csrftoken = response.cookies['csrftoken']

        print("[login] Got response, csrf: " + csrftoken)
        username = ''
        first_try = True
        while re.search('name="password"', response.text) is not None or first_try:
            if not first_try:
                print("[login] Invalid credentials")
            first_try = False
            username = input("Username: ")
            login_data = dict(username=username, password=getpass("Password: "), csrfmiddlewaretoken=csrftoken,
                              next='/')
            response = session.post(self.options.host + "/login/", data=login_data,
                                    headers=dict(Referer=self.options.host + "/login/"))

        csrftoken = re.search('name="csrfmiddlewaretoken" value="(.+)"', response.text).group(1)
        print("[login] Got response, csrf: " + csrftoken)
        first_try = True
        while re.search('name="csrfmiddlewaretoken" value="(.+)"', response.text) is not None or first_try:
            if not first_try:
                print("[login]", "Invalid token")
            first_try = False
            login_data = dict(token=input("Token: "), username=username, csrfmiddlewaretoken=csrftoken, next='/')
            response = session.post(self.options.host + "/otp_ok/", data=login_data,
                                    headers=dict(Referer=self.options.host + "/login/"))

        print("[login] Success, saving cookies...")
        session.cookies.save(ignore_discard=True)

        print("[login] Done.")
        self.cookies = session.cookies
        self.logged_in = True

    def download_file(self, url, fsize):
        try:
            local_filename = url.split('/')[-1]
            print("\rDownloading", local_filename)
            dsize = 0
            start = time.time()
            with requests.get(url, stream=True, cookies=self.cookies) as r:
                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)
                            dsize += len(chunk)
                            rate = dsize // (time.time() - start)
                            if not self.options.download_all:
                                print("\r" + sizeofmetric_fmt(fsize) + " " +
                                      str(round(dsize / fsize * 100)) + "% " +
                                      str(sizeofmetric_fmt(rate)) + "/sec ",
                                      "ETA:", human_readable_eta((fsize - dsize) / rate),
                                      end='     ')
                            else:
                                self.queue.put([len(chunk), False])
            if self.options.download_all:
                self.queue.put([0, True])

        except KeyboardInterrupt:
            return

    def logout(self):
        response = requests.get(self.options.host + '/accounts/logout/', cookies=self.cookies)
        if response.status_code == 200:
            print("[logout] Logged out.")
        else:
            print("[logout] Error logging out.")


def get_listing(session):
    response = requests.get(session.options.host + '/data_api/' + session.options.project, cookies=session.cookies)
    try:
        datafiles = json.loads(response.text)
        for file in datafiles:
            print(file['name'])
    except json.decoder.JSONDecodeError:
        print("[get_listing] Error reading response:", response.text)
        exit(1)


def download(session):
    response = requests.get(session.options.host + '/data_api/' + session.options.project, cookies=session.cookies)
    fsize = 0
    try:
        datafiles = json.loads(response.text)
        for file in datafiles:
            if file['name'] == session.options.download:
                fsize = file['size']
    except json.decoder.JSONDecodeError:
        print("[download] [get_listing] Error reading response: ", response.text)
        exit(1)

    url = session.options.host + '/session_files/' + session.options.project + '/' + session.options.download
    session.download_file(url, fsize)
    print()


def download_all(session):
    response = requests.get(session.options.host + '/data_api/' + session.options.project, cookies=session.cookies)
    try:
        datafiles = json.loads(response.text)
        dl_list = []
        dl_sum = 0
        linux = False
        if platform.platform().startswith('Linux'):
            linux = True
        else:
            print("Non-linux platform supports no multi-threaded downloading")
            session.options.download_all = False

        for file in datafiles:
            fsize = file['size']
            dl_sum += fsize
            local_filename = file['name']
            url = session.options.host + '/session_files/' + session.options.project + '/' + local_filename
            if linux:
                dl_list.append([url, fsize])
            else:
                session.download_file(url, fsize)
        if not linux:
            exit(0)

        current_processes = 0
        max_processes = int(session.options.threads)
        number_of_processes = len(dl_list)
        finished_processes = 0
        current_process = 0
        downloaded_bytes = 0
        processes = []

        for dl in dl_list:
            processes.append(Process(target=session.download_file, args=dl))

        start = time.time()

        while True:
            if current_processes < max_processes and finished_processes < number_of_processes and current_process < number_of_processes:
                processes[current_process].start()
                current_process += 1
                current_processes += 1
            if current_processes < max_processes and current_process < number_of_processes :
                continue

            status = session.queue.get()
            downloaded_bytes += status[0]
            if status[1]:
                current_processes -= 1
                finished_processes += 1
            rate = downloaded_bytes // (time.time() - start)
            print("\r", str(round(downloaded_bytes / dl_sum * 100))+"%",
                  "Downloading", sizeofmetric_fmt(downloaded_bytes), "of",
                  sizeofmetric_fmt(dl_sum),
                  str(sizeofmetric_fmt(rate)) + "/sec",
                  "ETA:", human_readable_eta((dl_sum - downloaded_bytes) / rate),
                  end='     ')
            if finished_processes == number_of_processes:
                print("\nDownloading complete")
                break

    except json.decoder.JSONDecodeError:
        print("[download_all] [get_listing] Error reading response: ", response.text)
        exit(1)


def main():
    options = Options(sys.argv)
    session = Session(options)
    if options.clear_cookies:
        session.logout()
    if options.listing:
        get_listing(session)
    if options.download:
        download(session)
    if options.download_all:
        download_all(session)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        exit(1)
