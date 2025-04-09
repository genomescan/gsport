from helpers.eta_readable import human_readable_eta

"""
Tests for the converter to human readable time

Each test checks that the function returns each time in the correct format

Author: Gonzalo Vela
"""


def test_one_second():
    """
    Test of one second
    """
    result = human_readable_eta(1)

    assert result == "1s"


def test_one_minute():
    """
    Test of one minute
    """
    result = human_readable_eta(60)

    assert result == "1m"


def test_one_hour():
    """
    Test of one hour
    """
    result = human_readable_eta(3600)

    assert result == "1h"


def test_one_day():
    """
    Test of one day
    """
    result = human_readable_eta(86400)

    assert result == "1d"


def test_minute_with_extra_seconds():
    """
    Test of one minute with a few seconds
    """
    result = human_readable_eta(65)

    assert result == "1m"


def test_hour_with_minutes():
    """
    Test of one hour with some minutes
    """
    result = human_readable_eta(3900)

    assert result == "1h5m"


def test_day_and_half():
    """
    Test of one day and half a day
    """
    result = human_readable_eta(129600)

    assert result == "1d12h"


def test_day_half_with_minutes():
    """
    Test of one day and half a day with some minutes
    """
    result = human_readable_eta(131400)

    assert result == "1d12h30m"


def test_zero_time():
    """
    Test of zero seconds
    """
    result = human_readable_eta(0)

    assert result == ""
