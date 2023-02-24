import re
import ipaddress

# ipv4_pattern = re.compile(r"""^
#             \s* # Leading whitespace
#             # Zero-width lookaheads to reject too many quartets
#             (?:
#                 # 6 quartets, ending IPv4 address; no wildcards
#                 (?:[0-9a-f]{1,4}(?::(?!:))){6}
#                     (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)
#                 (?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}
#             |
#                 # 0-5 quartets, wildcard, ending IPv4 address
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,4}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                     (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)
#                 (?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}
#             |
#                 # 0-4 quartets, wildcard, 0-1 quartets, ending IPv4 address
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,3}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:[0-9a-f]{1,4}(?::(?!:)))?
#                     (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)
#                 (?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}
#             |
#                 # 0-3 quartets, wildcard, 0-2 quartets, ending IPv4 address
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,2}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:[0-9a-f]{1,4}(?::(?!:))){0,2}
#                     (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)
#                 (?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}
#             |
#                 # 0-2 quartets, wildcard, 0-3 quartets, ending IPv4 address
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,1}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:[0-9a-f]{1,4}(?::(?!:))){0,3}
#                     (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)
#                 (?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}
#             |
#                 # 0-1 quartets, wildcard, 0-4 quartets, ending IPv4 address
#                 (?:[0-9a-f]{1,4}){0,1}
#                 (?:::(?!:))
#                 (?:[0-9a-f]{1,4}(?::(?!:))){0,4}
#                     (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)
#                 (?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}
#             |
#                 # wildcard, 0-5 quartets, ending IPv4 address
#                 (?:::(?!:))
#                 (?:[0-9a-f]{1,4}(?::(?!:))){0,5}
#                     (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)
#                 (?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}
#             |
#                 # 8 quartets; no wildcards
#                 (?:[0-9a-f]{1,4}(?::(?!:))){7}[0-9a-f]{1,4}
#             |
#                 # 0-7 quartets, wildcard
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,6}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#             |
#                 # 0-6 quartets, wildcard, 0-1 quartets
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,5}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:[0-9a-f]{1,4})?
#             |
#                 # 0-5 quartets, wildcard, 0-2 quartets
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,4}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,1}[0-9a-f]{1,4})?
#             |
#                 # 0-4 quartets, wildcard, 0-3 quartets
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,3}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,2}[0-9a-f]{1,4})?
#             |
#                 # 0-3 quartets, wildcard, 0-4 quartets
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,2}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,3}[0-9a-f]{1,4})?
#             |
#                 # 0-2 quartets, wildcard, 0-5 quartets
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,1}[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,4}[0-9a-f]{1,4})?
#             |
#                 # 0-1 quartets, wildcard, 0-6 quartets
#                 (?:[0-9a-f]{1,4})?
#                 (?:::(?!:))
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,5}[0-9a-f]{1,4})?
#             |
#                 # wildcard, 0-7 quartets
#                 (?:::(?!:))
#                 (?:(?:[0-9a-f]{1,4}(?::(?!:))){0,6}[0-9a-f]{1,4})?
#             )
#             (?:/(?:1(?:2[0-7]|[01]\d)|\d\d?))? # With an optional CIDR routing prefix (0-128)
#             \s* # Trailing whitespace
#             $""", re.VERBOSE | re.IGNORECASE | re.DOTALL)

# try:
#     ip = ipaddress.ip_address(sys.argv[1])
#     print('%s is a correct IP%s address.' % (ip, ip.version))
# except ValueError:
#     print('address/netmask is invalid: %s' % sys.argv[1])
# except:
#     print('Usage : %s  ip' % sys.argv[0])

# print(ipaddress.ip_address('997.0.0.1'))
# print(sys.argv)



def is_valid_ip_address(address):
    """Validates IPv4 addresses.

    Args:
        address (str): A string, the IPv4 address.
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def regex_get_Ipv4(string):
    """
    汉语注释：提取并验证IPv4地址
    ENGLISH COMMENT: Extract and validate IPv4 address
    """
    # 加上了“[]”符号内的限制
    #return re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', string)
    # return re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", string)

    
    # TODO but the pattern that use the mathching number can't verify whether it's a legitimate ipv4 address
    # get_ipv4_string= re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', string)

    if type(string) == str:

        get_ipv4_from_string= re.findall(r'\b[0-9]+(?:\.[0-9]+){3}(?:\/[\d]+)?\b', string, flags=re.M)
        get_ipv4_list = []
        for ip in get_ipv4_from_string:
            if is_valid_ip_address(ip):
                get_ipv4_list.append(ip)
            else:
                pass
        return get_ipv4_list
    else:
        print("Error : the input is not a string")
        return None
            
# case
# print(regex_get_Ipv4("'from mail2.oknotify2.com (mail2.oknotify2.com. [208.83.243.70/32]) \n by mx.google.com with ESMTP id dp5si2596299pdb.170.2015.06.03.14.12.03'"))



def Regular_extraction_of_ipv6_addresses(string):
    """
    Regular extraction of ipv6 addresses.
    """
    return re.findall(r'[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}', string)
    #return re.findall(r'\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b', string)

#检查IPv4地址是否合法
def vaild_ip_addr_v4(ipv4):
    """
    Checks if the IP address is valid.
    """


    # if re.match(r"^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$", ipv4):
    #     return True
    # else:
    #     return False
    # """
    # Checks if the IP address is valid.
    # """
    # if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_addr_v4):
    #     return True
    # else:
    #     return False

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

# """


# print(check_if_is_an_extranet_ipv4_address("66.249.65.56"))
# print(check_if_is_an_extranet_ipv6_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
# print(check_if_is_an_intranet_ipv4_address("66.249.65.56"))
# print(check_if_is_an_intranet_ipv6_address('2001:0db8:85a3:0000:0000:8a2e:0370:7334'))
# print(checks_if_the_ipv4_adress_is_valid("33.3333.33333.333"))
# print("checks_if_the_ipv6_adress_is_valid:",checks_if_the_ipv6_adress_is_valid('a001:0db8:85a3:0000:0000:8a2e:0370:7334'))
# print(Regular_extraction_of_ipv4_addresses("askldjas，66.249.65.56 kl123"))
# print(Regular_extraction_of_ipv6_addresses("han1a001:0db8:85a3:0000:0000:8a2e:0370:7334"))
