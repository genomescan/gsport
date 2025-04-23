import unittest
from unittest.mock import patch

import requests_mock

from main import main
from src.classes import Session

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
                "https://portal.genomescan.nl//logged_in_api/",
                text='{"logged_in": false}',
                status_code=200,
            )

            main()

            mock_login.assert_called_once()
