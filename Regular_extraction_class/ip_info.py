import re


def Regular_extraction_of_ipv4_addresses(string):
    """
    Regular extraction of ipv4 addresses.
    """
    return re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", string)

    

def Regular_extraction_of_ipv6_addresses(string):
    """
    Regular extraction of ipv6 addresses.
    """
    return re.findall(r'[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}', string)
    #return re.findall(r'\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b', string)

def make_sure_ipv4_is_a_string(ipv4):
    """
    Makes sure the IP address is a string.
    """
    if type(ipv4) == str:
        return ipv4
    else:
        return str(ipv4)


def make_sure_ipv6_is_a_string(ipv6):
    """
    Makes sure the IP address is a string.
    """
    if type(ipv6) == str:
        return ipv6
    else:
        return str(ipv6)

#检查IPv4地址是否合法
def checks_if_the_ipv4_adress_is_valid(ip_addr_v4):
    """
    Checks if the IP address is valid.
    """
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_addr_v4):
        return True
    else:
        return False

#检查IPv4地址是否合法
def checks_if_the_ipv6_adress_is_valid(ip_addr_v6):
    """
    Checks if the IP address is valid.
    """
    if re.match(r"^\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b$", ip_addr_v6):
        return True
    else:
        return False



def check_ipv4(string):
    """
    Checks if the IP address is valid.
    """
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", string):
        return True
    else:
        return False

def check_if_is_an_intranet_ipv4_address(ip_addr_v4):
    """
    Checks if the IP address is an intranet address.
    """
    if re.match(r"^(127|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))\.", ip_addr_v4):
        return True
    else:
        return False


def check_if_is_an_extranet_ipv4_address(ip_addr_v4):
    """
    Checks if the IP address is an intranet address.
    """
    if re.match(r"^(?!(10|127|192\.168|172\.(1[6-9]|2[0-9]|3[0-1])))\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_addr_v4):
        return True
    else:
        return False

def check_if_is_an_intranet_ipv6_address(ip_addr_v6):
    """
    Checks if the IP address is an intranet address.
    """
    if re.match(r"^(::1|fe80::|::)", ip_addr_v6):
    #if re.match(r"^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$", ip_addr_v6, re.I)
        return True
    else:
        return False


def check_if_is_an_extranet_ipv6_address(ip_addr_v6):
    """
    Checks if the IP address is an intranet address.
    """
    if re.match(r"^(?!(::1|fe80::|::))\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b$", ip_addr_v6):
        return True
    else:
        return False

"""
def checkIPAddress(ip):

    IP Address structure and content checker.
    
    # :param ip: IPv4/IPv6 address.
    # :type number: str
    # :return: 'Valid IP(type) Address', 'IP:x.x.x.x'
    # :rtype: tuple if valid IP Address input. String if Invalid IP is provided.
    
    # Example Command: 'checkIPAddress("2301:0db8:85a3:0000:0000:8a2e:0370:7334")'
    # Example Output: ('Valid IPv6 Address', '2301:0db8:85a3:0000:0000:8a2e:0370:7334')

    def ipv4_check(ip=ip):
        ipv4 = ip
        try:
            ipv4 = [ i.lstrip('0') if i != '0' else '0' for i in re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', ipv4)[0].split('.')]
            x=1
            for i in ipv4:
                if int(i) > 255:
                    del ipv4[x]
                    x+=1
            if ipv4 == []:
                return "Neither"
            elif '{}.{}.{}.{}'.format(ipv4[0], ipv4[1], ipv4[2], ipv4[3]) != ip:
                return "Neither"
            else:
                return '{}.{}.{}.{}'.format(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
        except:
            return "Neither"
        
    def ipv6_check(ip=ip):
        try:
            ipv6 = ip
            ipv6 = re.findall(r'[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}', ipv6)
            if ipv6 == []:
                return "Neither"
            elif ipv6[0] != ip:
                return "Neither"
            else:
                return ipv6[0]
        except:
            return "Neither"
        
    ipv4, ipv6 = ipv4_check(), ipv6_check()
    
    if ipv4 != "Neither":
        return "Valid IPv4 Address", ipv4
    elif ipv6 != "Neither":
        return "Valid IPv6 Address", ipv6
    else:
        return "Invalid IP Address"


def regex_parse(ip_address):
    regex = re.compile(r"(((([0-9A-Fa-f]{1,4}:){1,7}(:[0-9A-Fa-f]{1,4}){1,7})|(:(:[0-9A-Fa-f]{1,4}){1,7})|(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:))|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))")

    for i in range(0, len(ip_address)):
        result = regex.match(ip_address[i])
        print(ip_address[i])
        if result == "None":
            print("Fail\n")
        else:
            print("Pass!\n")

"""


print(check_if_is_an_extranet_ipv4_address("66.249.65.56"))
print(check_if_is_an_extranet_ipv6_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
print(check_if_is_an_intranet_ipv4_address("66.249.65.56"))
print(check_if_is_an_intranet_ipv6_address('2001:0db8:85a3:0000:0000:8a2e:0370:7334'))
print(checks_if_the_ipv4_adress_is_valid("33.3333.33333.333"))
print("checks_if_the_ipv6_adress_is_valid:",checks_if_the_ipv6_adress_is_valid('a001:0db8:85a3:0000:0000:8a2e:0370:7334'))
print(Regular_extraction_of_ipv4_addresses("askldjas，66.249.65.56 kl123"))
print(Regular_extraction_of_ipv6_addresses("han1a001:0db8:85a3:0000:0000:8a2e:0370:7334"))
