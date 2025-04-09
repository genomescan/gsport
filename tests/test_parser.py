import sys
from unittest.mock import patch

from classes import Options

"""
Tests for the argument parser in the Options class.

Each test checks that specific command-line arguments are correctly
parsed and assign the appropriate attributes.

Author: Gonzalo Vela
"""


@patch("sys.argv", ["script_name", "-H", "test_host"])
def test_host():
    """
    Test of host argument
    """
    options = Options(sys.argv)

    assert options.host == "test_host"


@patch("sys.argv", ["script_name", "-c"])
def test_clear_cookies():
    """
    Test of clear cookies flag
    """
    options = Options(sys.argv)

    assert options.clear_cookies


@patch("sys.argv", ["script_name", "list", "999", "-m"])
def test_set_see_directories():
    """
    Test of folder mode flag
    """
    options = Options(sys.argv)

    assert options.folder_mode


@patch("sys.argv", ["script_name", "list", "999", "-d", "test_dir"])
def test_set_directory():
    """
    Test of custom directory argument
    """
    options = Options(sys.argv)

    assert options.dir == "test_dir/"


@patch("sys.argv", ["script_name", "list", "999", "-r"])
def test_set_recursive():
    """
    Test of recursive flag
    """
    options = Options(sys.argv)

    assert options.recursive


@patch("sys.argv", ["script_name", "list", "999", "-m", "-d", "test_dir"])
def test_set_both_folder_files():
    """
    Test of folder mode with custom directory
    """
    options = Options(sys.argv)

    assert options.folder_mode
    assert options.dir == "test_dir/"


@patch("sys.argv", ["script_name", "list", "999", "-r", "-d", "test_dir"])
def test_set_both_recursive_files():
    """
    Test of recursive flag with custom directory
    """
    options = Options(sys.argv)

    assert options.recursive
    assert options.dir == "test_dir/"


@patch("sys.argv", ["script_name", "all", "999", "-o", "test_dir"])
def test_set_output():
    """
    Test of output directory argument
    """
    options = Options(sys.argv)

    assert options.output == "test_dir"


@patch("sys.argv", ["script_name", "all", "999", "-t", "4"])
def test_set_threads():
    """
    Test of thread count argument
    """
    options = Options(sys.argv)

    assert options.threads == 4


@patch("sys.argv", ["script_name", "all", "999", "-r"])
def test_set_recursive_download():
    """
    Test of recursive download flag
    """
    options = Options(sys.argv)

    assert options.recursive
