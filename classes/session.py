import hashlib
import json
import os
import re
import requests
import time

from getpass import getpass
from multiprocessing import Queue
from pathlib import Path

from gsport.helpers import *
from .MyCookie import MyCookieJar
from gsport.variables import GSPORT_VERSION

class Session:
    def __init__(self, options):
        self.options = options
        self.md5List = []
        self.localMd5List = []
        self.cookies = MyCookieJar(filename=os.path.join(str(Path.home()), '.gs_cookies.txt'))
        self.logged_in = False
        self.queue = Queue()
        self.process = Queue()
        self.includeFiles = []
        self.excludeFiles = []

        # Read the include and exclude filelist
        self.readFiles(options)

        try:
            self.cookies.load()
            if json.loads(requests.get(options.host + '/logged_in_api/', cookies=self.cookies).text)['logged_in']:
                self.logged_in = True
            else:
                self.login()
        except FileNotFoundError:
            print("[session] No cookies found. Logging in...")
            self.login()

    def readFiles(self, options):
        if options.includeFile and os.path.exists(options.includeFile):
            self.includeFiles = open(options.includeFile, 'r').read().split('\n')

        if options.excludeFile and os.path.exists(options.excludeFile):
            self.excludeFiles = open(options.excludeFile, 'r').read().split('\n')

        if options.checksumFile and os.path.exists(options.checksumFile):
            lines = open(options.checksumFile, 'r').read()
            self.localMd5List.extend([list.split(', ') for list in lines.split("\n") if list.split(', ') != ['']])

    def login(self):
        print("[login] Opening session...")
        session = requests.Session()
        session.cookies = MyCookieJar(os.path.join(str(Path.home()), '.gs_cookies.txt'))
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
                                    headers={"Referer": self.options.host + "/login/",
                                             "User-Agent": "gsport " + GSPORT_VERSION
                                             })

        print("[login] Success, saving cookies...")
        session.cookies.save(ignore_discard=True)

        print("[login] Done.")
        self.cookies = session.cookies
        self.logged_in = True

    def download_file(self, url, fsize, fname):
        try:
            dsize = 0
            start = time.time()
            with requests.get(url, stream=True, cookies=self.cookies) as r:
                self.options.dir = '/'.join(self.options.dir.split('/')[:-1])

                if self.options.dir != '':
                    if not os.path.isdir(os.path.join(self.options.dir)):
                        os.makedirs(os.path.join(self.options.dir))
                else:
                    self.options.dir = ''

                if self.options.path and os.path.isdir(self.options.path):
                    fpath = os.path.join(self.options.path, fname)
                else:
                    fpath = fname

                # Use the filename from this point onwards. For the full path use fpath.
                fname = os.path.basename(fname)
                # With ignore parameter, you will only download the file if it does not exist on the system.
                if self.options.ignore and os.path.exists(fpath):
                    print('File "' + fname + '" already exists. Ignoring download...')
                    return

                # With force parameter, you will always re-download, even if the file exists and is the same.
                elif not self.options.force and os.path.exists(fpath):
                    md5Hash = hashlib.md5(open(fpath, 'rb').read()).hexdigest()

                    # Only skip if the MD5 hash + filename exists in the md5List.
                    if [md5Hash, fname] in self.md5List:
                        print('File "' + fname + '" already exists and MD5 check is valid. Skipping download...')
                        return
                    elif self.options.checksumFile and [md5Hash, fname] in self.localMd5List:
                        print(
                            'File "' + fname + '" already exists and MD5 check is valid. Skipping download... (validated via local MD5 list).')
                        return
                    else:
                        print('File "' + fname + '" exists but MD5 does not match. Re-downloading...')

                if self.includeFiles and not fname in self.includeFiles:
                    print('File "' + fname + '" is not in the "include" file. Skipping download...')
                    return

                if self.excludeFiles and fname in self.excludeFiles:
                    print('File "' + fname + '" is in the "exclude" file. Skipping download...')
                    return

                with open(fpath, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)
                            dsize += len(chunk)
                            rate = dsize // (time.time() - start)
                            if rate != 0:
                                eta = human_readable_eta((fsize - dsize) / rate)
                            else:
                                eta = "NA"
                            if not self.options.download_all:
                                print("\r" + sizeofmetric_fmt(fsize) + " " +
                                      str(round(dsize / fsize * 100)) + "% " +
                                      str(sizeofmetric_fmt(rate)) + "/sec ",
                                      "ETA:", eta,
                                      end='     ')
                            else:
                                self.queue.put([len(chunk), False])

                if os.path.exists(fpath):
                    md5Hash = hashlib.md5(open(fpath, 'rb').read()).hexdigest()
                    if [md5Hash, fname] in self.md5List:
                        print('File "' + fname + '" successfully downloaded.')
                    elif self.options.checksumFile and [md5Hash, fname] in self.localMd5List:
                        print('File "' + fname + '" successfully downloaded (validated via local MD5 list).')
                    elif self.options.checksumFile and [md5Hash, fname] not in self.localMd5List:
                        # Open the file for writing.
                        f = open(self.options.checksumFile, 'a')
                        f.write(md5Hash + ', ' + fname + "\n")
                        f.close()
                        self.localMd5List.append([md5Hash, fname])
                        print(
                            'File "' + fname + '" downloaded, MD5 check added to local md5 list, file removed and re-downloading for md5 validation...')
                        os.remove(fpath)

                        # Re-download the file
                        self.download_file(url, fsize, fname)
                    else:
                        print('File "' + fname + '" downloaded but did not pass the MD5 check.')

            if self.options.download_all:
                self.queue.put([0, True])
        except KeyboardInterrupt:
            return
        return

    def logout(self):
        response = requests.get(self.options.host + '/accounts/logout/', cookies=self.cookies)
        if response.status_code == 200:
            print("[logout] Logged out.")
        else:
            print("[logout] Error logging out.")