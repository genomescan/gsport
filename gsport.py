#!/usr/bin/env python3
"""
GSPORT command-line tool for accessing GenomeScan Customer Portal
---
(C) GenomeScan B.V. 2019
(C) GenomeScan B.V. 2020 - Update
N.J. de Water - Software Developer
"""

import getopt
import hashlib
import http.cookiejar
import json
import os
import platform
import re
import requests
import sys
import time

from getpass import getpass
from multiprocessing import Process, Queue
from pathlib import Path

GSPORT_VERSION = "1.8.0"

def version():
    print( GSPORT_VERSION )


def usage():
    print( """
Usage: gsport [options]
GSPORT command-line tool for accessing GenomeScan Customer Portal

Options
-H --host [host], default: https://portal.genomescan.nl
-p --project [project] project (required with -l, -d, -a)
-l --list return a list of all files
-s --size return a list with the size
-d --download [filename]
-a --download-all download all files from project -p or --project
-f --force downloading files even if they already exist 
-c --clear-cookies clear session/cookies
-t --workers [n] allow n concurrent workers (defaults to number of logical cpu cores) (works only on Linux)
--dirs show directories instead of files (combined with -l or --list)
--cd [dir] show files (or directories) in dir, 
     dirs can be appended with forward slashes: / (eg. "Analysis/Sample 1", with quotes)
     or Analysis/s1/bam (without spaces, no quotes needed)
-r --recursive lists/downloads complete tree from --cd [dir] or everything if no --cd option is given 
-h --help prints this help
-v --version show gsport version
-i --ignore Ignore MD5 checksum result and download only files not on the system
-I --includeFile Path to file containing list of files to include in the download. One file per line and save the file using the UTF-8 encoding. only works with the -a flag.
-E --excludeFile Path to file containing list of files to exclude from downloading. One file per line and save the file using the UTF-8 encoding. only works with the -a flag.
-C --checksumFile Path to the file containing a lise of all the file checksums. It will store the md5 checksum of all downloaded files. If the checksum of the file to download is not provided, the script will download the file twice to test if the MD5 match.
-P --path Local location to store the files to.

Note: Using --dirs together with -r / --recursive has no effect

Example usage: gsport -p 100000 -l shows all the files under that project
               gsport -p 100000 -ls shows all the files under that project with the filesize
               gsport -p 100000 -l --dirs shows all the folders/directories under that project
               gsport -p 100000 -l --cd Analysis shows all the files under Analysis for that project
               gsport -p 100000 -l -r shows all the files and folders in Analysis in a tree structure
               gsport -p 100000 -l --dirs cd Analysis shows all the folders under Analysis for that project
               gsport -p 100000 -a -r downloads all the files and folders for that project
               gsport -p 100000 -a -r --cd Analysis downloads all the files and folder under Analysis for that project
               gsport -p 100000 -a --cd Analysis downloads only the files directly under Analysis, no subfolder or files in there.
               gsport -p 100000 -a --cd Analysis/s1 downloads only the files directly under Analysis/s1
               gsport -p 100000 -a -I "C:\\project\\include.txt"
               gsport -p 100000 -a -E "C:\\project\\exclude.txt"
               gsport -p 100000 -a -C "C:\\project\\localChecksums.md5"
               gsport -p 100000 -a -P "C:\\project\\exclude.txt"
""" )


def human_readable_eta( seconds ):
    days = seconds // 86400
    hours = seconds // 3600 % 24
    minutes = seconds // 60 % 60
    seconds = seconds % 60
    ret = str( round( days ) ) + 'd' if days > 0 else ''
    ret += str( round( hours ) ) + 'h' if hours > 0 else ''
    ret += str( round( minutes ) ) + 'm' if minutes > 0 else ''
    ret += str( round( seconds ) ) + 's' if seconds > 0 and minutes < 1 else ''
    return ret


def sizeofmetric_fmt( num, suffix = 'B' ):
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs( num ) < 1000.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1000.0
    return "%.1f %s%s" % (num, 'Y', suffix)


class Options:
    def __init__( self, argv ):
        self.download = None
        self.download_all = False
        self.force = False
        self.host = "https://portal.genomescan.nl/"
        self.listing = False
        self.listingSize = False
        self.ignore = False
        self.help = False
        self.project = None
        self.no_options = True
        self.found_project = False
        self.clear_cookies = False
        self.threads = os.cpu_count()
        self.dirs = False
        self.dir = '.'
        self.recursive = False
        self.includeFile = None
        self.excludeFile = None
        self.checksumFile = None
        self.path = None

        try:
            opts, args = getopt.getopt( argv[1:],
                                        "H:p:lsd:afchrivt:I:E:C:P:",
                                        ["host=", "project=", "list", "size",
                                         "download=", "download-all", "force", "threads", "version",
                                         "clear-cookies", "help", "dirs", "cd=", "recursive", "ignore",
                                         "includeFile=", "excludeFile=", "checksumFile=", "path="] )

        except getopt.GetoptError as err:
            print( err )
            usage()
            exit( 1 )

        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                exit()
            elif o in ("-H", "--host"):
                self.host = a.strip()
            elif o in ("-p", "--project"):
                self.project = a.strip()
                self.found_project = True
            elif o in ("-l", "--list"):
                self.listing = True
                self.no_options = False
            elif o in ("-s", "--size"):
                self.listing = True
                self.listingSize = True
                self.no_options = False
            elif o in ("-d", "--download"):
                self.download = a.strip()
                self.no_options = False
            elif o in ("-t", "--threads"):
                self.threads = a.strip()
            elif o in ("-a", "--download-all"):
                self.download_all = True
                self.no_options = False
            elif o in ("-f", "--force"):
                self.force = True
            elif o in ("-i", "--ignore"):
                self.ignore = True
            elif o in ("-c", "--clear-cookies"):
                self.clear_cookies = True
                self.no_options = False
            elif o in ("-I", "--includeFile"):
                if os.path.isfile( a.strip() ):
                    self.includeFile = a.strip()
                    print( 'Include file: ' + self.includeFile )
                else:
                    print( 'File for -I parameter does not exist: ' + a.strip() )
                    exit()
            elif o in ("-E", "--excludeFile"):
                if os.path.isfile( a.strip() ):
                    self.excludeFile = a.strip()
                    print( 'Exclude file: ' + self.excludeFile )
                else:
                    print( 'File for -E parameter does not exist: ' + a.strip() )
                    exit()
            elif o in ("-C", "--checksumFile"):
                if not os.path.isfile( a.strip() ):
                    # Create a new file.
                    open( a.strip(), "x" )
                    print( 'Local checksum file did not exist. New file created.' )
                self.checksumFile = a.strip()
                print( 'Local checksum file: ' + self.checksumFile )

            elif o in ("-P", "--path"):
                if os.path.isdir( a.strip() ):
                    self.path = a.strip()
                else:
                    print( a.strip() + ' is not a folder.' )
            elif o in ("--dirs",):
                self.dirs = True
            elif o in ("--cd",):
                self.dir = a.strip() + "/"
            elif o in ("-r", "--recursive"):
                self.recursive = True
            elif o in ("-v", "--version"):
                version()
                exit()
            else:
                assert False

        if (self.listing or self.download or self.download_all) and not self.found_project:
            print( "[error] listing, list size, download and download all require a project" )
            usage()
            exit( 1 )
        if self.found_project and self.no_options:
            print( "[error] project with no other option, what do you want to do?" )
            usage()
            exit( 1 )
        if self.download is not None and self.download_all:
            print( "[error] cannot download one file and all files (option -d and -a)" )
            usage()
            exit( 1 )
        if not self.download_all:
            self.threads = 1


class Session:
    def __init__( self, options ):
        self.options = options
        self.md5List = []
        self.localMd5List = []
        self.cookies = http.cookiejar.MozillaCookieJar( filename = os.path.join( str( Path.home() ), '.gs_cookies.txt' ) )
        self.logged_in = False
        self.queue = Queue()
        self.process = Queue()
        self.includeFiles = []
        self.excludeFiles = []

        # Read the include and exclude filelist
        self.readFiles( options )

        try:
            self.cookies.load()
            if json.loads( requests.get( options.host + '/logged_in_api/', cookies = self.cookies ).text )['logged_in']:
                self.logged_in = True
            else:
                self.login()
        except FileNotFoundError:
            print( "[session] No cookies found. Logging in..." )
            self.login()

    def readFiles( self, options ):
        if options.includeFile and os.path.exists( options.includeFile ):
            self.includeFiles = open( options.includeFile, 'r' ).read().split( '\n' )

        if options.excludeFile and os.path.exists( options.excludeFile ):
            self.excludeFiles = open( options.excludeFile, 'r' ).read().split( '\n' )

        if options.checksumFile and os.path.exists( options.checksumFile ):
            lines = open( options.checksumFile, 'r' ).read()
            self.localMd5List.extend( [list.split( ', ' ) for list in lines.split( "\n" ) if list.split( ', ' ) != ['']] )

    def login( self ):
        print( "[login] Opening session..." )
        session = requests.Session()
        session.cookies = http.cookiejar.MozillaCookieJar( os.path.join( str( Path.home() ), '.gs_cookies.txt' ) )
        print( "[login] Get login page" )
        response = session.get( self.options.host + "/login/" )
        csrftoken = response.cookies['csrftoken']

        username = ''
        first_try = True
        while re.search( 'name="password"', response.text ) is not None or first_try:
            if not first_try:
                print( "[login] Invalid credentials" )
            first_try = False
            username = input( "Username: " )
            login_data = dict( username = username, password = getpass( "Password: " ), csrfmiddlewaretoken = csrftoken,
                               next = '/' )
            response = session.post( self.options.host + "/login/", data = login_data,
                                     headers = dict( Referer = self.options.host + "/login/" ) )

        csrftoken = re.search( 'name="csrfmiddlewaretoken" value="(.+)"', response.text ).group( 1 )

        first_try = True
        while re.search( 'name="csrfmiddlewaretoken" value="(.+)"', response.text ) is not None or first_try:
            if not first_try:
                print( "[login]", "Invalid token" )
            first_try = False
            login_data = dict( token = input( "Token: " ), username = username, csrfmiddlewaretoken = csrftoken, next = '/' )
            response = session.post( self.options.host + "/otp_ok/", data = login_data,
                                     headers = {"Referer": self.options.host + "/login/",
                                                "User-Agent": "gsport " + GSPORT_VERSION
                                                } )

        print( "[login] Success, saving cookies..." )
        session.cookies.save( ignore_discard = True )

        print( "[login] Done." )
        self.cookies = session.cookies
        self.logged_in = True

    def download_file( self, url, fsize, fname ):
        try:
            dsize = 0
            start = time.time()
            with requests.get( url, stream = True, cookies = self.cookies ) as r:
                self.options.dir = '/'.join( self.options.dir.split( '/' )[:-1] )

                if self.options.dir != '':
                    if not os.path.isdir( os.path.join( self.options.dir ) ):
                        os.makedirs( os.path.join( self.options.dir ) )
                else:
                    self.options.dir = '.'

                if self.options.path and os.path.isdir( self.options.path ):
                    fpath = os.path.join( self.options.path, fname )
                else:
                    fpath = fname

                # Use the filename from this point onwards. For the full path use fpath.
                fname = os.path.basename( fname )
                # With ignore parameter, you will only download the file if it does not exist on the system.
                if self.options.ignore and os.path.exists( fpath ):
                    print( 'File "' + fname + '" already exists. Ignoring download...' )
                    return

                # With force parameter, you will always re-download, even if the file exists and is the same.
                elif not self.options.force and os.path.exists( fpath ):
                    md5Hash = hashlib.md5( open( fpath, 'rb' ).read() ).hexdigest()

                    # Only skip if the MD5 hash + filename exists in the md5List.
                    if [md5Hash, fname] in self.md5List:
                        print( 'File "' + fname + '" already exists and MD5 check is valid. Skipping download...' )
                        return
                    elif self.options.checksumFile and [md5Hash, fname] in self.localMd5List:
                        print( 'File "' + fname + '" already exists and MD5 check is valid. Skipping download... (validated via local MD5 list).' )
                        return
                    else:
                        print( 'File "' + fname + '" exists but MD5 does not match. Re-downloading...' )

                if self.includeFiles and not fname in self.includeFiles:
                    print( 'File "' + fname + '" is not in the "include" file. Skipping download...' )
                    return

                if self.excludeFiles and fname in self.excludeFiles:
                    print( 'File "' + fname + '" is in the "exclude" file. Skipping download...' )
                    return

                with open( fpath, 'wb' ) as f:
                    for chunk in r.iter_content( chunk_size = 8192 ):
                        if chunk:  # filter out keep-alive new chunks
                            f.write( chunk )
                            dsize += len( chunk )
                            rate = dsize // (time.time() - start)
                            if not self.options.download_all:
                                print( "\r" + sizeofmetric_fmt( fsize ) + " " +
                                       str( round( dsize / fsize * 100 ) ) + "% " +
                                       str( sizeofmetric_fmt( rate ) ) + "/sec ",
                                       "ETA:", human_readable_eta( (fsize - dsize) / rate ),
                                       end = '     ' )
                            else:
                                self.queue.put( [len( chunk ), False] )

                if os.path.exists( fpath ):
                    md5Hash = hashlib.md5( open( fpath, 'rb' ).read() ).hexdigest()
                    if [md5Hash, fname] in self.md5List:
                        print( 'File "' + fname + '" successfully downloaded.' )
                    elif self.options.checksumFile and [md5Hash, fname] in self.localMd5List:
                        print( 'File "' + fname + '" successfully downloaded (validated via local MD5 list).' )
                    elif self.options.checksumFile and [md5Hash, fname] not in self.localMd5List:
                        # Open the file for writing.
                        f = open( self.options.checksumFile, 'a' )
                        f.write( md5Hash + ', ' + fname + "\n" )
                        f.close()
                        self.localMd5List.append( [md5Hash, fname] )
                        print( 'File "' + fname + '" downloaded, MD5 check added to local md5 list, file removed and re-downloading for md5 validation...' )
                        os.remove( fpath )

                        # Re-download the file
                        self.download_file( url, fsize, fname )
                    else:
                        print( 'File "' + fname + '" downloaded but did not pass the MD5 check.' )

            if self.options.download_all:
                self.queue.put( [0, True] )
        except KeyboardInterrupt:
            return
        return

    def logout( self ):
        response = requests.get( self.options.host + '/accounts/logout/', cookies = self.cookies )
        if response.status_code == 200:
            print( "[logout] Logged out." )
        else:
            print( "[logout] Error logging out." )


def print_rec( dic, depth ):
    for item in dic:
        if item['type'] == 'directory':
            for i in range( depth * 2 ):
                print( "  ", end = '' )
            print( "└──", item["name"] )
            print_rec( item['children'], depth + 1 )
        else:
            for i in range( depth * 2 ):
                print( "  ", end = '' )
            print( "├──", item["name"], 'Size: ', item['size'], 'bytes' )


def get_listing( session ):
    if session.options.recursive:
        response = requests.get( session.options.host + '/data_api_recursive/' +
                                 session.options.project,
                                 cookies = session.cookies,
                                 params = {"cd": session.options.dir} )
        try:
            datafiles = json.loads( response.text )
            print_rec( datafiles["children"], 0 )
        except json.decoder.JSONDecodeError:
            print( "[get_listing] Error reading response:", response.text )
            exit( 1 )
    else:
        response = requests.get( session.options.host + '/data_api2/' +
                                 session.options.project +
                                 ('/y' if session.options.dirs is True else '/n'),
                                 cookies = session.cookies,
                                 params = {"cd": session.options.dir} )
        try:
            datafiles = json.loads( response.text )
            for file in datafiles:
                if session.options.listingSize:
                    print( file['name'] + '   (' + sizeofmetric_fmt( file['size'] ) + ')' )
                else:
                    print( file['name'] )
        except json.decoder.JSONDecodeError:
            print( "[get_listing] Error reading response:", response.text )
            exit( 1 )


def download( session ):
    response = requests.get( session.options.host + '/data_api2/' + session.options.project + '/n',
                             cookies = session.cookies,
                             params = {"cd": session.options.dir} )
    fsize = 0
    fname = ''
    try:
        datafiles = json.loads( response.text )

        # Obtain the MD5 hash of the files, when the file to download is a '.gz' file.
        if not session.md5List and '.gz' in session.options.download:
            for file in datafiles:
                if file['name'] == 'checksums.md5':
                    # Get the code to obtain the file
                    response = requests.get( session.options.host + '/gen_session_file/', cookies = session.cookies,
                                             params = {"project": session.options.project,
                                                       "filename": "/" + session.options.dir + "/" +
                                                                   file['name']
                                                       } )
                    # Create the URL to obtain the file (one time use)
                    url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text
                    md5 = requests.get( url, stream = True, cookies = session.cookies )

                    if session.options.checksumFile:
                        # Open the file once for writing. Then loop for writing and then close.
                        f = open( session.options.checksumFile, 'a' )

                    # Split the MD5 file to a list<str,str>
                    for list in md5.text.split( "\n" ):
                        md5Obj = list.split( '  ' )
                        session.md5List.append( md5Obj )

                        # If a local checksum file is provided, add the online ones to the local file.
                        if session.options.checksumFile and md5Obj not in session.localMd5List:
                            # Add the new md5 value to the local file.
                            f.write( md5Obj[0] + ', ' + md5Obj[1] + "\n" )

                            # Store the object in the list for reference.
                            session.localMd5List.append( md5Obj )

                    if session.options.checksumFile:
                        f.close()

        for file in datafiles:
            if file['name'] == session.options.download:
                fsize = file['size']
                if fsize == 0:
                    fsize = 1
                fname = file['name']
    except json.decoder.JSONDecodeError:
        print( "[download] [get_listing] Error reading response: ", response.text )
        exit( 1 )
    response = requests.get( session.options.host + '/gen_session_file/', cookies = session.cookies,
                             params = {"project": session.options.project,
                                       "filename": "/" + session.options.dir + "/" +
                                                   session.options.download
                                       } )
    url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text
    session.download_file( url, fsize, fname )
    print()


def get_list( res, session_dir ):

    flist = []

    def print_list( dic, path ):
        for item in dic:
            if item['type'] == 'directory':
                d = os.path.join( path, item['name'] )
                if not os.path.isdir( d ):
                    try:
                        os.makedirs( d )
                    except FileExistsError:
                        pass  # this can be the case with multithreading
                print_list( item['children'], d )
            else:
                flist.append( {"name": path + "/" + item["name"],
                               "size": item["size"]} )

    print_list( json.loads( res )['children'], session_dir )
    return flist


def download_all( session ):
    datafiles = []
    if session.options.recursive:
        response = requests.get( session.options.host + '/data_api_recursive/' +
                                 session.options.project,
                                 cookies = session.cookies,
                                 params = {"cd": session.options.dir} )
        try:
            datafiles = get_list( response.text, session.options.dir )
        except json.decoder.JSONDecodeError:
            print( "[get_listing] Error reading response:", response.text )
            exit( 1 )
    else:
        response = requests.get( session.options.host + '/data_api2/' + session.options.project + '/n',
                                 cookies = session.cookies,
                                 params = {"cd": session.options.dir} )
        try:
            datafiles = json.loads( response.text )
        except json.decoder.JSONDecodeError:
            print( "[get_listing] Error reading response:", response.text )
            exit( 1 )

    # Obtain the MD5 hash of the files, when the file to download is a '.gz' file.
    for file in datafiles:
        if 'checksums.md5' in file['name']:
            # Get the code to obtain the file
            response = requests.get( session.options.host + '/gen_session_file/', cookies = session.cookies,
                                     params = {"project": session.options.project,
                                               "filename": "/" + session.options.dir + "/" +
                                                           file['name']
                                               } )
            # Create the URL to obtain the file (one time use)
            url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text
            md5 = requests.get( url, stream = True, cookies = session.cookies )

            if session.options.checksumFile:
                # Open the file once for writing. Then loop for writing and then close.
                f = open( session.options.checksumFile, 'a' )

            # Split the MD5 file to a list<str,str>
            for list in md5.text.split( "\n" ):
                # if empty, skip.
                if not (list and list.strip()):
                    continue

                md5Obj = list.split( '  ' )
                session.md5List.append( md5Obj )

                # If a local checksum file is provided, add the online ones to the local file.
                if session.options.checksumFile and md5Obj not in session.localMd5List:
                    # Add the new md5 value to the local file.
                    f.write( md5Obj[0] + ', ' + md5Obj[1] + "\n" )

                    # Store the object in the list for reference.
                    session.localMd5List.append( md5Obj )

            if session.options.checksumFile:
                f.close()


    dl_list = []
    dl_sum = 0
    linux = False
    if platform.platform().startswith( 'Linux' ):
        linux = True
    else:
        print( "Non-linux platform supports no multi-threaded downloading" )
        session.options.download_all = False

    for file in datafiles:
        fsize = file['size'] if file['size'] != 0 else 1
        dl_sum += fsize
        filename = "/" + (session.options.dir if not session.options.recursive else '') + "/" + file['name']
        response = requests.get( session.options.host + '/gen_session_file/', cookies = session.cookies,
                                 params = {"project": session.options.project,
                                           "filename": filename
                                           } )
        url = session.options.host + '/session_files2/' + session.options.project + "/" + response.text

        if linux:
            dl_list.append( [url, fsize, file['name']] )
        else:
            session.download_file( url, fsize, file['name'] )
    if not linux:
        exit( 0 )

    current_processes = 0
    max_processes = min( 8, int( session.options.threads ) )
    number_of_processes = len( dl_list )
    finished_processes = 0
    current_process = 0
    downloaded_bytes = 0
    processes = []

    for dl in dl_list:
        processes.append( Process( target = session.download_file, args = dl ) )

    start = time.time()
    started = []
    while True:
        if current_processes < max_processes and finished_processes < number_of_processes and current_process < number_of_processes:
            processes[current_process].start()
            started.append( processes[current_process] )
            current_process += 1
            current_processes += 1
        if current_processes < max_processes and current_process < number_of_processes:
            continue

        status = session.queue.get()
        downloaded_bytes += status[0]
        for process in started:
            if not process.is_alive():
                if process.exitcode is not None:
                    process.close()
                    started.remove( process )

        if status[1]:
            current_processes -= 1
            finished_processes += 1
        rate = downloaded_bytes // (time.time() - start)
        if dl_sum > 100:  # preventing devision by zero errors
            estimatedtimeofarrival="Never" #it was this or "After the heat death of the universe"
            if rate > 0:
                  estimatedtimeofarrival=human_readable_eta((dl_sum - downloaded_bytes) / rate) 
            print("\r", str(round(downloaded_bytes / dl_sum * 100))+"%",
                  "Downloading", sizeofmetric_fmt(downloaded_bytes), "of",
                  sizeofmetric_fmt(dl_sum),
                  str(sizeofmetric_fmt(rate)) + "/sec",
                  "ETA:", estimatedtimeofarrival,
                  end='     ')

        if finished_processes == number_of_processes:
            print( "\nDownloading complete" )
            break


def main():
    options = Options( sys.argv )
    session = Session( options )
    if options.clear_cookies:
        session.logout()
    if options.listing:
        get_listing( session )
    if options.download:
        download( session )
    if options.download_all:
        download_all( session )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        exit( 1 )
