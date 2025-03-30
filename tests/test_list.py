import unittest
from unittest.mock import patch

from main import main

class TestMain(unittest.TestCase):
    @patch("sys.argv", ["script_name", "list", "999", "-r"])
    def test_main(self):
        main()

if __name__ == "__main__":
    unittest.main()
