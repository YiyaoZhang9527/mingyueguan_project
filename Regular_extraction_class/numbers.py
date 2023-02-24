import re


def Regular_extraction_of_number(string):
    """
    Regular extraction of number.
    """
    return re.findall(r"[0-9]+", string)