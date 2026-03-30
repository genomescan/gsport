import sys

import multiprocessing
from src.classes import Options, Session
from src.helpers.downloads import download
from src.helpers.listings import get_listing, list_all_projects
from src.helpers.print_functions import print_error


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
        multiprocessing.freeze_support()
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(1)
    except KeyError:
        print_error(
            "An error has occurred, please try again later or contact the development team"
        )
        sys.exit(1)
