import sys

from src.classes import Options, Session
from src.helpers.downloads import download
from src.helpers.listings import get_listing, list_all_projects


def main():
    options = Options(sys.argv)
    session = Session(options)
    if options.get_projects:
        list_all_projects(session)
    if options.listing:
        get_listing(session)
    elif options.download or options.download_all:
        download(session)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        exit(1)
