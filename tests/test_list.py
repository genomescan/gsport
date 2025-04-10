import re
import sys
import unittest
from io import StringIO
from unittest.mock import patch

import requests_mock

from main import main

"""
Tests for the list command

Each tests checks that the list command displays the corresponding file and directories

Author: Gonzalo Vela
"""


class TestListcommand(unittest.TestCase):
    def remove_ansi_escape_sequences(self, text):
        """
        Helper function to remove escape sequences for the ease of string comparison
        """
        ansi_escape = re.compile(r"\x1b\[[0-9;]*[mK]")

        return ansi_escape.sub("", text)

    @patch("sys.argv", ["script_name", "list", "999", "-r"])
    def test_recursive(self):
        """
        Test list command when recursive is set
        """
        with requests_mock.Mocker() as m:
            m.get("https://portal.genomescan.nl//logged_in_api/", text='{"logged_in": true}', status_code=200)

            with open("tests/assets/recursive_mock.json", "r") as recursive_mock_file:
                recursive_mock = recursive_mock_file.read()

            m.get("https://portal.genomescan.nl//data_api_recursive/999?cd=.%2F", text=recursive_mock)

            captured = StringIO()
            sys.stdout = captured

            main()

            captured = captured.getvalue()

            expected_output = "[session] cookies found.\n└── test_map_salah\n    ├── 3660_Color_palette (1).pdf Size:  517854\n└── test_999\n    ├── test_10G.txt Size:  10737418240\n    ├── test2_10G.txt Size:  10737418240\n"

            assert self.remove_ansi_escape_sequences(captured) == expected_output

    @patch("sys.argv", ["script_name", "list", "999", "-m"])
    def test_folder_mode(self):
        """
        Test list command when folder mode is set
        """
        with requests_mock.Mocker() as m:
            m.get("https://portal.genomescan.nl//logged_in_api/", text='{"logged_in": true}', status_code=200)

            with open("tests/assets/recursive_mock.json", "r") as recursive_mock_file:
                recursive_mock = recursive_mock_file.read()

            m.get("https://portal.genomescan.nl//data_api_recursive/999?cd=.%2F", text=recursive_mock)

            captured = StringIO()
            sys.stdout = captured

            main()

            captured = captured.getvalue()

            expected_output = "[session] cookies found.\ntest_map_salah\ntest_999\n"

            assert self.remove_ansi_escape_sequences(captured) == expected_output

    @patch("sys.argv", ["script_name", "list", "999", "-d", "test_999"])
    def test_show_files_from_project(self):
        """
        Test list command shows files under the projects
        """
        with requests_mock.Mocker() as m:
            m.get("https://portal.genomescan.nl//logged_in_api/", text='{"logged_in": true}', status_code=200)

            with open("tests/assets/project_files.json", "r") as project_files:
                project_files = project_files.read()

            m.get("https://portal.genomescan.nl//data_api_recursive/999?cd=test_999%2F", text=project_files)

            captured = StringIO()
            sys.stdout = captured

            main()

            captured = captured.getvalue()

            expected_output = (
                "[session] cookies found.\ntest_10G.txt Size:  10737418240\ntest2_10G.txt Size:  10737418240\n"
            )

            assert self.remove_ansi_escape_sequences(captured) == expected_output

    @patch("sys.argv", ["script_name", "list", "999", "-m", "-d", "test_999"])
    def test_show_files_folders_from_project(self):
        """
        Test list command shows files and folders under a project
        """
        with requests_mock.Mocker() as m:
            m.get("https://portal.genomescan.nl//logged_in_api/", text='{"logged_in": true}', status_code=200)

            with open("tests/assets/project_files.json", "r") as project_files:
                project_files = project_files.read()

            m.get("https://portal.genomescan.nl//data_api_recursive/999?cd=test_999%2F", text=project_files)

            captured = StringIO()
            sys.stdout = captured

            main()

            captured = captured.getvalue()

            expected_output = "[session] cookies found.\ntest_map_salah\ntest_10G.txt\ntest2_10G.txt\n"

            assert self.remove_ansi_escape_sequences(captured) == expected_output

    @patch("sys.argv", ["script_name", "list", "999", "-r", "-d", "test_999"])
    def test_show_project_recursively(self):
        """
        Tests list command shows files recursively
        """
        with requests_mock.Mocker() as m:
            m.get("https://portal.genomescan.nl//logged_in_api/", text='{"logged_in": true}', status_code=200)

            with open("tests/assets/project_files.json", "r") as project_files:
                project_files = project_files.read()

            m.get("https://portal.genomescan.nl//data_api_recursive/999?cd=test_999%2F", text=project_files)

            captured = StringIO()
            sys.stdout = captured

            main()

            captured = captured.getvalue()

            expected_output = "[session] cookies found.\n└── test_map_salah\n    ├── 3660_Color_palette (1).pdf Size:  517854\n├── test_10G.txt Size:  10737418240\n├── test2_10G.txt Size:  10737418240\n"

            assert self.remove_ansi_escape_sequences(captured) == expected_output
