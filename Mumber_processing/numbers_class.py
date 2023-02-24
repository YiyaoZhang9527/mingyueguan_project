from re import findall

def regex_find_number(string):
    """
    Regular extraction of number.
    """
    return findall(r"[0-9]+", string)


