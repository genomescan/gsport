import unittest

from src.helpers.sizeofmetric import (  # Adjust to match your structure
    size_of_metric_fmt,
)

"""
Tests for the converter to metric size function

Each test checks that the function returns each size in the correct format

Author: Gonzalo Vela
"""


class TestMetricSize(unittest.TestCase):
    def test_bytes(self):
        """
        Test of only bytes
        """
        result = size_of_metric_fmt(999)
        assert result == "999.0 B"

    def test_kilobyte(self):
        """
        Test of one kilobyte
        """
        result = size_of_metric_fmt(1000)
        assert result == "1.0 KB"

    def test_kilobyte_rounding(self):
        """
        Test for kilobyte rounding
        """
        result = size_of_metric_fmt(1536)
        assert result == "1.5 KB"

    def test_megabyte(self):
        """
        Test of one megabyte
        """
        result = size_of_metric_fmt(1_000_000)
        assert result == "1.0 MB"

    def test_gigabyte(self):
        """
        Test of one gigabyte
        """
        result = size_of_metric_fmt(1_000_000_000)
        assert result == "1.0 GB"

    def test_terabyte(self):
        """
        Test of one terabyte
        """
        result = size_of_metric_fmt(1_000_000_000_000)
        assert result == "1.0 TB"

    def test_yottabyte(self):
        """
        Tests if yotabytes are returned
        """
        result = size_of_metric_fmt(1e27)
        assert result == "1000.0 YB"

    def test_float_input(self):
        """
        Test input with decimals
        """
        result = size_of_metric_fmt(123456.78)
        assert result == "123.5 KB"

    def test_custom_suffix(self):
        """
        Test when a custom suffix is given
        """
        result = size_of_metric_fmt(1000, suffix="bps")
        assert result == "1.0 Kbps"

    def test_zero_value(self):
        """
        Test edge case of a zero value
        """
        result = size_of_metric_fmt(0)
        assert result == "0.0 B"

    def test_negative_value(self):
        """
        Test edge case of a negative value
        """
        result = size_of_metric_fmt(-1500)
        assert result == "-1.5 KB"
