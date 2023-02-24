import re

def Regular_extraction_of_mobile_phone_numbers(string):
    """
    Regular extraction of mobile phone numbers.
    """
    return re.findall(r"1[345789]\d{9}", string)


def Regular_extraction_of_email_addresses(string):
    """
    Regular extraction of email addresses.
    """
    return re.findall(r"[\w\.-]+@[\w\.-]+", string)


def Regular_extraction_of_urls(string):
    """
    Regular extraction of urls from chinese.
    """
    return re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", string)
    
