import re
import unittest
from unittest.mock import patch
import requests_mock
import sys
from io import StringIO
from main import main
import pytest

# Function to remove ANSI escape sequences (colors)
def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mK]')
    return ansi_escape.sub('', text)

@patch("sys.argv", ["script_name", "list", "999", "-r"])
def test_recursive(capsys):
    with requests_mock.Mocker() as m:
        m.get("https://portal.genomescan.nl//logged_in_api/", text="{\"logged_in\": true}",  status_code=200)

        with open("tests/assets/recursive_mock.json", 'r') as recursive_mock_file:
            recursive_mock = recursive_mock_file.read()

        m.get(f"https://portal.genomescan.nl//data_api_recursive/999?cd=.%2F", text=recursive_mock)

        main()

        captured, error = capsys.readouterr()

        expected_output = "[session] cookies found.\n└── test_map_salah\n    ├── 3660_Color_palette (1).pdf Size:  517854\n└── test_999\n    ├── test_10G.txt Size:  10737418240\n    ├── test2_10G.txt Size:  10737418240\n"

        assert remove_ansi_escape_sequences(captured) == expected_output

@patch("sys.argv", ["script_name", "list", "999", "-m"])
def test_folder_mode(capsys):
    with requests_mock.Mocker() as m:
        m.get("https://portal.genomescan.nl//logged_in_api/", text="{\"logged_in\": true}",  status_code=200)

        with open("tests/assets/recursive_mock.json", 'r') as recursive_mock_file:
            recursive_mock = recursive_mock_file.read()

        m.get(f"https://portal.genomescan.nl//data_api_recursive/999?cd=.%2F", text=recursive_mock)

        main()

        captured, error = capsys.readouterr()

        expected_output = "[session] cookies found.\ntest_map_salah\ntest_999\n"

        assert remove_ansi_escape_sequences(captured) == expected_output

@patch("sys.argv", ["script_name", "list", "999", "-d", "test_999"])
def test_show_files_from_project(capsys):
    with requests_mock.Mocker() as m:
        m.get("https://portal.genomescan.nl//logged_in_api/", text="{\"logged_in\": true}",  status_code=200)

        with open("tests/assets/project_files.json", 'r') as project_files:
            project_files = project_files.read()

        m.get(f"https://portal.genomescan.nl//data_api_recursive/999?cd=test_999%2F", text=project_files)

        main()

        captured, error = capsys.readouterr()

        expected_output = "[session] cookies found.\ntest_10G.txt Size:  10737418240\ntest2_10G.txt Size:  10737418240\n"

        assert remove_ansi_escape_sequences(captured) == expected_output

@patch("sys.argv", ["script_name", "list", "999","-m", "-d", "test_999"])
def test_show_files_folders_from_project(capsys):
    with requests_mock.Mocker() as m:
        m.get("https://portal.genomescan.nl//logged_in_api/", text="{\"logged_in\": true}",  status_code=200)

        with open("tests/assets/project_files.json", 'r') as project_files:
            project_files = project_files.read()

        m.get(f"https://portal.genomescan.nl//data_api_recursive/999?cd=test_999%2F", text=project_files)

        main()

        captured, error = capsys.readouterr()

        expected_output = "[session] cookies found.\ntest_map_salah\ntest_10G.txt\ntest2_10G.txt\n"

        assert remove_ansi_escape_sequences(captured) == expected_output

@patch("sys.argv", ["script_name", "list", "999","-r", "-d", "test_999"])
def test_show_project_recursively(capsys):
    with requests_mock.Mocker() as m:
        m.get("https://portal.genomescan.nl//logged_in_api/", text="{\"logged_in\": true}",  status_code=200)

        with open("tests/assets/project_files.json", 'r') as project_files:
            project_files = project_files.read()

        m.get(f"https://portal.genomescan.nl//data_api_recursive/999?cd=test_999%2F", text=project_files)

        main()

        captured, error = capsys.readouterr()

        expected_output = "[session] cookies found.\n└── test_map_salah\n    ├── 3660_Color_palette (1).pdf Size:  517854\n├── test_10G.txt Size:  10737418240\n├── test2_10G.txt Size:  10737418240\n"

        assert remove_ansi_escape_sequences(captured) == expected_output