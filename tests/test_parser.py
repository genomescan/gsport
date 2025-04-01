import re
import unittest
from unittest.mock import patch
import requests_mock
import sys
from io import StringIO

import variables
from classes import Options, Session
from main import main
import pytest

""" Test parser """
@patch("sys.argv", ["script_name", "-H", "test_host"])
def test_host():
    options = Options(sys.argv)
    session = Session(options)

    assert session.options.host == "test_host"

@patch("sys.argv", ["script_name", "-c"])
def test_clear_cookies(capsys):
    options = Options(sys.argv)

    assert options.clear_cookies

@patch("sys.argv", ["script_name", "-v"])
def test_clear_cookies(capsys):

    with patch('main.sys.exit') as exit_mock:
        main()

    captured, error = capsys.readouterr()

    lines = captured.split('\n')

    assert lines[0] == "gsport " + variables.GSPORT_VERSION


""" Test parser for list commands """
@patch("sys.argv", ["script_name","list","999", "-m"])
def test_set_directory():
    options = Options(sys.argv)

    assert options.dirs

@patch("sys.argv", ["script_name","list","999", "-d", "test_dir"])
def test_set_directory():
    options = Options(sys.argv)

    assert options.dir == "test_dir/"



""" Test parser for all commands """
@patch("sys.argv", ["script_name","all","999", "-o", "test_dir"])
def test_set_output():
    options = Options(sys.argv)

    assert options.output == "test_dir"