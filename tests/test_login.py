import unittest
from unittest.mock import patch

import requests_mock

from main import main
from src.classes import Session
from src.variables import HOST_URL, LOGGED_IN_URL

"""
Tests for the login process

Author: Gonzalo Vela
"""


class TestLogin(unittest.TestCase):
    @patch("sys.argv", ["script_name"])
    @patch.object(Session, "login")
    def test_login_false(self, mock_login):
        """
        Test that unauthorized cookies trigger the login process.
        """

        with requests_mock.Mocker() as m:
            m.get(
                f"{HOST_URL}{LOGGED_IN_URL}",
                text='{"logged_in": false}',
                status_code=200,
            )

            main()

            mock_login.assert_called_once()
