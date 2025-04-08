import sys
from unittest.mock import patch

from classes import Options


@patch("sys.argv", ["script_name", "-H", "test_host"])
def test_host():
    options = Options(sys.argv)

    assert options.host == "test_host"


@patch("sys.argv", ["script_name", "-c"])
def test_clear_cookies(capsys):
    options = Options(sys.argv)

    assert options.clear_cookies


@patch("sys.argv", ["script_name", "list", "999", "-m"])
def test_set_see_directories():
    options = Options(sys.argv)

    assert options.folder_mode


@patch("sys.argv", ["script_name", "list", "999", "-d", "test_dir"])
def test_set_directory():
    options = Options(sys.argv)

    assert options.dir == "test_dir/"


@patch("sys.argv", ["script_name", "list", "999", "-r"])
def test_set_recursive():
    options = Options(sys.argv)

    assert options.recursive


@patch("sys.argv", ["script_name", "list", "999", "-m", "-d", "test_dir"])
def test_set_both_folder_files():
    options = Options(sys.argv)

    assert options.folder_mode
    assert options.dir == "test_dir/"


@patch("sys.argv", ["script_name", "list", "999", "-r", "-d", "test_dir"])
def test_set_both_recursive_files():
    options = Options(sys.argv)

    assert options.recursive
    assert options.dir == "test_dir/"


@patch("sys.argv", ["script_name", "all", "999", "-o", "test_dir"])
def test_set_output():
    options = Options(sys.argv)

    assert options.output == "test_dir"


@patch("sys.argv", ["script_name", "all", "999", "-t", "4"])
def test_set_threads():
    options = Options(sys.argv)

    assert options.threads == 4


@patch("sys.argv", ["script_name", "all", "999", "-r"])
def test_set_recursive_download():
    options = Options(sys.argv)

    assert options.recursive
