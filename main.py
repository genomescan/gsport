import sys

from classes import Options, Session
from helpers import download, download_all, get_listing


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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        exit(1)
