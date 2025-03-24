import sys

from classes import Options, Session
from helpers.listings import list_all_projects, get_listing
from helpers.downloads import download


def main():
    options = Options(sys.argv)
    session = Session(options)
    if options.get_projects:
        list_all_projects(session)
    if options.listing:
        get_listing(session)
    elif options.download or options.download_all:
        download(session)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        exit(1)