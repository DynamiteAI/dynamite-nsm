import re


def validate_name(s):
    """
    Must be between 5 and 30 characters and
        - contain only alphanumeric and hyphen/underscore characters,
        - and start and end with alphanumeric characters

    :param s: Test string
    :return: True, if meets name conditions
    """
    return bool(5 <= len(s) <= 30 and re.search(r'^[a-zA-Z0-9]([\w -]*[a-zA-Z0-9]$)', s))
