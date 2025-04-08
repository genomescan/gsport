from helpers.eta_readable import human_readable_eta


# TODO: change all of the strings to variables, create fancy comments
def test_one_second():
    result = human_readable_eta(1)

    assert result == "1s"


def test_one_minute():
    result = human_readable_eta(60)

    assert result == "1m"


def test_one_hour():
    result = human_readable_eta(3600)

    assert result == "1h"


def test_one_day():
    result = human_readable_eta(86400)

    assert result == "1d"


def test_minute_second():
    """
    Test a minute with some seconds (should only show the minute)
    """

    result = human_readable_eta(65)

    assert result == "1m"


def test_hour_minute():
    """
    Test an hour with some minutes
    """

    result = human_readable_eta(3900)

    assert result == "1h5m"


def test_day_hour():
    """
    Test a day and a half
    """

    result = human_readable_eta(129600)

    assert result == "1d12h"


def test_day_hour_minute():
    """
    Test a day and half with some minutes
    """

    result = human_readable_eta(131400)

    assert result == "1d12h30m"


def test_zero_seconds():
    """
    Test edge case of no providing seconds
    """

    result = human_readable_eta(0)

    assert result == ""
