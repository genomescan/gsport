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
import os

def usage():
    print("""
Usage: gsport [options]
GSPORT command-line tool for accessing GenomeScan Customer Portal

Options
-H --host [host], default: https://portal.genomescan.nl
-p --project [project] project (required with -l, -d, -a)
-l --list list
-d --download [filename] download
-a --download-all download all files from project -p or --project
-c --clear-cookies clear session/cookies
-t --threads [n] allow n concurrent threads (works only on Linux)
   --dirs show directories instead of files (combined with -l or --list)
   --cd [dir] show files (or directories) in dir, 
              dirs can be appended with forward slashes: / (eg. "Analysis/Sample 1", with quotes)
              or Analysis/s1/bam (without spaces, no quotes needed)
-r --recursive lists/downloads complete tree from --cd [dir] or everything if no --cd option is given 
-h --help prints this help

Note: Using --dirs together with -r / --recursive has no effect

Example usage: gsport -p 100000 -l shows all the files under that project
               gsport -p 100000 -l --dirs shows all the folders/directories under that project
               gsport -p 100000 -l --cd Analysis shows all the files under Analysis for that project
               gsport -p 100000 -l -r shows all the files and folders in Analysis in a tree structure
               gsport -p 100000 -l --dirs cd Analysis shows all the folders under Analysis for that project
               gsport -p 100000 -a -r downloads all the files and folders for that project
               gsport -p 100000 -a -r --cd Analysis downloads all the files and folder under Analysis for that project
               gsport -p 100000 -a --cd Analysis downloads only the files directly under Analysis, no subfolder or files in there.
               gsport -p 100000 -a --cd Analysis/s1 downloads only the files directly under Analysis/s1
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
        self.dirs = False
        self.dir = '.'
        self.recursive = False

        try:
            opts, args = getopt.getopt(argv[1:],
                                       "H:p:ld:achrt:",
                                       ["host=", "project=", "list",
                                        "download=", "download-all", "threads"
                                        "clear-cookies", "help", "dirs", "cd=", "recursive"])

        except getopt.GetoptError as err:
            print(err)
            usage()
            exit(1)

        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                exit()
            elif o in ("-H", "--host"):
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
            elif o in ("--dirs",):
                self.dirs = True
            elif o in ("--cd",):
                self.dir = a
            elif o in ("-r", "--recursive"):
                self.recursive = True
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

    def download_file(self, url, fsize, fname):
        try:
            local_filename = url.split('/')[-1]
            print("\nDownloading", fname)
            dsize = 0
            start = time.time()
            with requests.get(url, stream=True, cookies=self.cookies) as r:
                self.options.dir = '/'.join(self.options.dir.split('/')[:-1])

                if self.options.dir != '':
                    if not os.path.isdir(os.path.join(self.options.dir)):
                        os.makedirs(os.path.join(self.options.dir))
                else:
                    self.options.dir = '.'
                with open(os.path.join(self.options.dir, fname), 'wb') as f:
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


def print_rec(dic, depth):
    for item in dic:
        if item['type'] == 'directory':
            for i in range(depth*2):
                print("  ", end='')
            print("└──", item["name"])
            print_rec(item['children'], depth+1)
        else:
            for i in range(depth*2):
                print("  ", end='')
            print("├──", item["name"], 'Size: ', item['size'], 'bytes')


def get_listing(session):
    if session.options.recursive:
        response = requests.post(session.options.host + '/data_api_recursive/' +
                                 session.options.project,
                                 cookies=session.cookies,
                                 data={"cd": session.options.dir})
        try:
            datafiles = json.loads(response.text)
            print_rec(datafiles["children"], 0)
        except json.decoder.JSONDecodeError:
            print("[get_listing] Error reading response:", response.text)
            exit(1)
    else:
        response = requests.post(session.options.host + '/data_api/' +
                                 session.options.project +
                                 ('/y' if session.options.dirs is True else '/n'),
                                 cookies=session.cookies,
                                 data={"cd": session.options.dir})
        try:
            datafiles = json.loads(response.text)
            for file in datafiles:
                print(file['name'])
        except json.decoder.JSONDecodeError:
            print("[get_listing] Error reading response:", response.text)
            exit(1)


def download(session):
    response = requests.post(session.options.host + '/data_api/' + session.options.project + '/n',
                            cookies=session.cookies,
                            data={"cd": session.options.dir})
    fsize = 0
    fname = ''
    try:
        datafiles = json.loads(response.text)
        for file in datafiles:
            if file['name'] == session.options.download:
                fsize = file['size']
                if fsize == 0:
                    fsize = 1
                fname = file['name']
    except json.decoder.JSONDecodeError:
        print("[download] [get_listing] Error reading response: ", response.text)
        exit(1)
    response = requests.post(session.options.host + '/gen_session_file/', cookies=session.cookies,
                        data={"project": session.options.project,
                              "filename": "/" + session.options.dir + "/" +
                                          session.options.download
                              })
    url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text
    # url = session.options.host + '/session_files/' + session.options.project + '/' + session.options.download
    session.download_file(url, fsize, fname)
    print()


def get_list(res, session_dir):

    flist = []

    def print_list(dic, path):
        for item in dic:
            if item['type'] == 'directory':
                # print(path + "/" + item["name"])
                d = os.path.join(path, item['name'])
                print(d)
                if not os.path.isdir(d):
                    os.makedirs(d)
                print_list(item['children'], d)
            else:
                flist.append({"name": path + "/" + item["name"],
                              "size": item["size"]})

    print_list(json.loads(res)['children'], session_dir)
    return flist


def download_all(session):
    datafiles = []
    if session.options.recursive:
        response = requests.post(session.options.host + '/data_api_recursive/' +
                                 session.options.project,
                                 cookies=session.cookies,
                                 data={"cd": session.options.dir})
        try:
            datafiles = get_list(response.text, session.options.dir)
            print(datafiles, session.options.dir)
        except json.decoder.JSONDecodeError:
            print("[get_listing] Error reading response:", response.text)
            exit(1)
    else:
        response = requests.post(session.options.host + '/data_api/' + session.options.project + '/n',
                                 cookies=session.cookies,
                                 data={"cd": session.options.dir})
        try:
            datafiles = json.loads(response.text)
        except json.decoder.JSONDecodeError:
            print("[get_listing] Error reading response:", response.text)
            exit(1)

    dl_list = []
    dl_sum = 0
    linux = False
    if platform.platform().startswith('Linux'):
        linux = True
    else:
        print("Non-linux platform supports no multi-threaded downloading")
        session.options.download_all = False

    for file in datafiles:
        fsize = file['size'] if file['size'] != 0 else 1
        print('fsize', fsize)
        dl_sum += fsize
        local_filename = file['name']
        filename = "/" + (session.options.dir if not session.options.recursive else '') + "/" + file['name']
        response = requests.post(session.options.host + '/gen_session_file/', cookies=session.cookies,
                                 data={"project": session.options.project,
                                       "filename": filename
                                       })
        url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text

        if linux:
            dl_list.append([url, fsize, file['name']])
        else:
            session.download_file(url, fsize, file['name'])
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
        if dl_sum > 10:
            print("\r", str(round(downloaded_bytes / dl_sum * 100))+"%",
                  "Downloading", sizeofmetric_fmt(downloaded_bytes), "of",
                  sizeofmetric_fmt(dl_sum),
                  str(sizeofmetric_fmt(rate)) + "/sec",
                  "ETA:", human_readable_eta((dl_sum - downloaded_bytes) / rate),
                  end='     ')
        if finished_processes == number_of_processes:
            print("\nDownloading complete")
            break



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
