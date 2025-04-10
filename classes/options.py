import getopt
import os

from helpers import usage
from variables import GSPORT_VERSION


def version():
    print(GSPORT_VERSION)


class Options:
    def __init__(self, argv):
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
        self.dir = ""
        self.recursive = False
        self.includeFile = None
        self.excludeFile = None
        self.checksumFile = None
        self.path = None

        try:
            opts, args = getopt.getopt(
                argv[1:],
                "H:p:lsd:afchrivt:I:E:C:P:",
                [
                    "host=",
                    "project=",
                    "list",
                    "size",
                    "download=",
                    "download-all",
                    "force",
                    "threads",
                    "version",
                    "clear-cookies",
                    "help",
                    "dirs",
                    "cd=",
                    "recursive",
                    "ignore",
                    "includeFile=",
                    "excludeFile=",
                    "checksumFile=",
                    "path=",
                ],
            )

        except getopt.GetoptError as err:
            print(err)
            usage()
            exit(1)

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
                if os.path.isfile(a.strip()):
                    self.includeFile = a.strip()
                    print("Include file: " + self.includeFile)
                else:
                    print("File for -I parameter does not exist: " + a.strip())
                    exit()
            elif o in ("-E", "--excludeFile"):
                if os.path.isfile(a.strip()):
                    self.excludeFile = a.strip()
                    print("Exclude file: " + self.excludeFile)
                else:
                    print("File for -E parameter does not exist: " + a.strip())
                    exit()
            elif o in ("-C", "--checksumFile"):
                if not os.path.isfile(a.strip()):
                    # Create a new file.
                    open(a.strip(), "x")
                    print("Local checksum file did not exist. New file created.")
                self.checksumFile = a.strip()
                print("Local checksum file: " + self.checksumFile)

            elif o in ("-P", "--path"):
                if os.path.isdir(a.strip()):
                    self.path = a.strip()
                else:
                    print(a.strip() + " is not a folder.")
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
            print("[error] listing, list size, download and download all require a project")
            usage()
            exit(1)
        if self.found_project and self.no_options:
            print("[error] project with no other option, what do you want to do?")
            usage()
            exit(1)
        if self.download is not None and self.download_all:
            print("[error] cannot download one file and all files (option -d and -a)")
            usage()
            exit(1)
        if not self.download_all:
            self.threads = 1
