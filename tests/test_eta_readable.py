import unittest

from src.helpers.eta_readable import human_readable_eta

"""
Tests for the converter to human readable time

Each test checks that the function returns each time in the correct format

Author: Gonzalo Vela
"""


class TestETAReadable(unittest.TestCase):
    def test_one_second(self):
        """
        Test of one second
        """
        result = human_readable_eta(1)
        self.assertEqual(result, "1s")

    def test_one_minute(self):
        """
        Test of one minute
        """
        result = human_readable_eta(60)
        self.assertEqual(result, "1m")

    def test_one_hour(self):
        """
        Test of one hour
        """
        result = human_readable_eta(3600)
        self.assertEqual(result, "1h")

    def test_one_day(self):
        """
        Test of one day
        """
        result = human_readable_eta(86400)
        self.assertEqual(result, "1d")

    def test_minute_with_extra_seconds(self):
        """
        Test of one minute with a few seconds
        """
        result = human_readable_eta(65)
        self.assertEqual(result, "1m")

    def test_hour_with_minutes(self):
        """
        Test of one hour with some minutes
        """
        result = human_readable_eta(3900)
        self.assertEqual(result, "1h5m")

    def test_day_and_half(self):
        """
        Test of one day and half a day
        """
        result = human_readable_eta(129600)
        self.assertEqual(result, "1d12h")

    def test_day_half_with_minutes(self):
        """
        Test of one day and half a day with some minutes
        """
        result = human_readable_eta(131400)

        self.assertEqual(result, "1d12h30m")

    def test_zero_time(self):
        """
        Test of zero seconds
        """
        result = human_readable_eta(0)
        self.assertEqual(result, "")
