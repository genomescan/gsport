import argparse
import os

from src.helpers import print_functions
from src.variables import (
    DOWNLOAD_ALL_EXAMPLE_MESSAGE,
    DOWNLOAD_EXAMPLE_MESSAGE,
    GSPORT_VERSION,
    HOST_URL,
    LIST_EXAMPLE_MESSAGE,
)


class Options:
    def __init__(self, argv):
        # Create the parser for gsport.
        parser = argparse.ArgumentParser(
            prog="gsport",
            description="GSPORT command-line tool for accessing GenomeScans new Customer Portal",
        )
        subparsers = parser.add_subparsers(
            title="subcommands",
            description="valid subcommands",
            help="use subcommand with -h for additional help",
            dest="subparser_name",
        )

        # Parser commands.
        parser.add_argument(
            "-H",
            "--host",
            default=HOST_URL,
            help="The host site default is %(default)s",
        )
        parser.add_argument(
            "-c",
            "--clear-cookies",
            action="store_true",
            help="clear cookies and logout session",
        )
        parser.add_argument(
            "-v",
            "--version",
            help="show the software version and exit",
            action="version",
            version=f"%(prog)s {GSPORT_VERSION}",
        )
        parser.add_argument(
            "-p",
            "--projects",
            help="show all the projects that a user has access to",
            action="store_true",
        )

        # List of shared commands for subcommands.
        project_parser = argparse.ArgumentParser(add_help=False)
        project_parser.add_argument(
            "PROJECT", help="[projectcode] for specific projects"
        )
        download_and_listing_shared = argparse.ArgumentParser(add_help=False)
        download_and_listing_shared.add_argument(
            "-d",
            "--cd",
            default=".",
            help="files (or directories) in dir, dirs can be appended with forward"
            " slashes: / (eg. 'Analysis/Sample 1', with quotes) or Analysis/s1/bam"
            " (without spaces, no quotes needed)",
        )
        downloads_shared = argparse.ArgumentParser(add_help=False)
        downloads_shared.add_argument(
            "-o",
            "--output",
            default=".",
            help="directory that downloaded files will go in, default is current directory",
        )

        # List subcommand.
        subparser_list = subparsers.add_parser(
            "list",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="prints the output",
            description="this subcommand prints the output",
            epilog=LIST_EXAMPLE_MESSAGE,
            parents=[project_parser, download_and_listing_shared],
        ) 
        subparser_list.add_argument(
            "-md5",
            "--md5sums",
            action="store_true",
            default=False,
            help="Print a flat list of the paths and md5sums for all files within the list command",
        )
        list_options_group = subparser_list.add_mutually_exclusive_group()
        list_options_group.add_argument(
            "-m", "--dirs", action="store_true", help="show directories"
        )
        list_options_group.add_argument(
            "-r",
            "--recursive",
            action="store_true",
            help="recursive complete tree from --cd "
            "[dir] or everything if no --cd option is given ",
        )
        subparser_list.set_defaults(func=self.L)

        # Download subcommand.
        subparser_download = subparsers.add_parser(
            "download",
            help="download specified files",
            description="this allows the download of individual files, use the full path for files",
            epilog=DOWNLOAD_EXAMPLE_MESSAGE,
            parents=[project_parser, downloads_shared],
        )
        subparser_download.add_argument(
            "FILE", help="files to download separated by spaces", nargs="+"
        )
        subparser_download.set_defaults(func=self.D)

        # Download all subcommand.
        subparser_download_all = subparsers.add_parser(
            "all",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="download all files",
            description="this subcommand allows the download of all files",
            epilog=DOWNLOAD_ALL_EXAMPLE_MESSAGE,
            parents=[project_parser, download_and_listing_shared, downloads_shared],
        )
        subparser_download_all.add_argument(
            "-t", "--threads", type=int, default=os.cpu_count()
        )
        subparser_download_all.add_argument(
            "-r",
            "--recursive",
            action="store_true",
            help="recursive complete tree from --cd "
            "[dir] or everything if no --cd option is given ",
        )
        subparser_download_all.set_defaults(func=self.A)

        # Parse arguments.
        args = parser.parse_args()

        self.host: str = (
            args.host
        )  # The host site that gsport should make connection to.
        self.download: list | None = None  # When the download option is being used the files are saved in a list.
        self.download_all: bool = False  # Is the all option being used.
        self.listing: bool = False  # Is the list option being used.
        self.recursive: bool = False  # Is the recursive option being used.
        self.project: str | None = (
            None  # The projectcode that the user requests things from.
        )
        self.show_md5 = False
        self.clear_cookies: bool = (
            args.clear_cookies
        )  # Clear the cookies, must be logged in to clear cookies.
        self.threads: int = (
            1  # The amount of threads being used for multithreading, Linux only.
        )
        self.folder_mode: bool = False  # Show only directories in list sub-command.
        self.dir: str = ""
        self.get_projects: bool = args.projects  # Show all user projects?
        self.output: str = "."  # The directory that the files are being saved to.

        if args.host != parser.get_default("host"):
            print_functions.print_info(f"Using alternative host {args.host}")

        if args.subparser_name is not None:
            args.func(args)

    def L(self, args):
        """
            Gets called when the subcommand L is used.
        :param args: The argument Namespace object.
        :return: None
        """
        self.folder_mode = args.dirs
        self.dir = args.cd + "/"
        self.recursive = args.recursive
        self.project = args.PROJECT
        self.listing = True
        self.show_md5 = args.md5sums

    def A(self, args):
        """
            Gets called when the subcommand A is used.
        :param args: The argument Namespace object.
        :return: None
        """
        self.project = args.PROJECT
        self.dir = args.cd + "/"
        self.recursive = args.recursive
        self.threads = args.threads
        self.download_all = True
        self.output = args.output

    def D(self, args):
        """
            Gets called when the subcommand D is used.
        :param args: The argument Namespace object.
        :return: None
        """
        self.download = args.FILE
        self.project = args.PROJECT
        self.threads = os.cpu_count()
        self.output = args.output
