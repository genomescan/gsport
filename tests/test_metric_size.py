from helpers.sizeofmetric import size_of_metric_fmt  # Adjust to match your structure

"""
Tests for the converter to metric size function

Each test checks that the function returns each size in the correct format

Author: Gonzalo Vela
"""


def test_bytes():
    """
    Test of only bytes
    """
    result = size_of_metric_fmt(999)

    assert result == "999.0 B"


def test_kilobyte():
    """
    Test of one kilobyte
    """
    result = size_of_metric_fmt(1000)

    assert result == "1.0 KB"


def test_kilobyte_rounding():
    """
    Test for kilobyte rounding
    """
    result = size_of_metric_fmt(1536)

    assert result == "1.5 KB"


def test_megabyte():
    """
    Test of one megabyte
    """
    result = size_of_metric_fmt(1_000_000)

    assert result == "1.0 MB"


def test_gigabyte():
    """
    Test of one gigabyte
    """
    result = size_of_metric_fmt(1_000_000_000)

    assert result == "1.0 GB"


def test_terabyte():
    """
    Test of one terabyte
    """
    result = size_of_metric_fmt(1_000_000_000_000)

    assert result == "1.0 TB"


def test_yottabyte():
    """
    Tests if yotabytes are returned
    """
    result = size_of_metric_fmt(1e27)

    assert result == "1000.0 YB"


def test_float_input():
    """
    Test input with decimals
    """
    result = size_of_metric_fmt(123456.78)

    assert result == "123.5 KB"


def test_custom_suffix():
    """
    Test when a custom suffix is given
    """
    result = size_of_metric_fmt(1000, suffix="bps")

    assert result == "1.0 Kbps"


def test_zero_value():
    """
    Test edge case of a zero value
    """
    result = size_of_metric_fmt(0)

    assert result == "0.0 B"


def test_negative_value():
    """
    Test edge case of a negative value
    """
    result = size_of_metric_fmt(-1500)

    assert result == "-1.5 KB"
