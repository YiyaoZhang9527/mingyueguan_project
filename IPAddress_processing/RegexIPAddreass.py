import re
import ipaddress

def is_valid_ip_address(address):
    """
    Validates IPv4 addresses.
    验证ipv4地址是否合法
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
    if type(string) == str:
        result = []
        error_list = []
        find_ipv4 = re.findall(r'\b[0-9]+(?:\.[0-9]+){3}(?:\/[\d]+)?\b', string, flags=re.M)
        
        for ipv4 in find_ipv4:
            if is_valid_ip_address(ipv4):
                result.append(ipv4)
            else:
                error_list.append(ipv4)
        return result
    else:
        return ValueError("the input is not a string")

    
def regex_get_Ipv6(string,return_error=False):
    """
    汉语注释：提取并验证IPv4地址
    ENGLISH COMMENT: Extract and validate IPv4 address
    """
    if type(string) == str:
        threshold_value = 3
        result = []
        error_list = []
        # TODO: IPv6 address
        # ipv6_pattern = re.compile(r"(?:(?:[\da-fA-F]{1,4}\:){6}(?:[\da-fA-F]{1,4}\:[\da-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)))|\:\:(?:[\da-fA-F]{1,4}\:){5}(?:[\da-fA-F]{1,4}\:[\da-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)))|(?:[\da-fA-F]{1,4})?\:\:(?:[\da-fA-F]{1,4}\:){4}(?:[\da-fA-F]{1,4}\:[\da-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)))|(?:(?:[\da-fA-F]{1,4}\:){0,1}[\da-fA-F]{1,4})?\:\:(?:[\da-fA-F]{1,4}\:){3}(?:[\da-fA-F]{1,4}\:[\da-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)))|(?:(?:[\da-fA-F]{1,4}\:){0,2}[\da-fA-F]{1,4})?\:\:(?:[\da-fA-F]{1,4}\:){2}(?:[\da-fA-F]{1,4}\:[\da-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)))|(?:(?:[\da-fA-F]{1,4}\:){0,3}[\da-fA-F]{1,4})?\:\:(?:[\da-fA-F]{1,4}\:)(?:[\da-fA-F]{1,4}\:[\da-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)))|(?:(?:[\da-fA-F]{1,4}\:){0,4}[\da-fA-F]{1,4})?\:\:(?:[\da-fA-F]{1,4}\:[\da-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)))|(?:(?:[\da-fA-F]{1,4}\:){0,5}[\da-fA-F]{1,4})?\:\:[\da-fA-F]{1,4}|(?:(?:[\da-fA-F]{1,4}\:){0,6}[\da-fA-F]{1,4})?\:\:)")
        
        ipv6_pattern = re.compile(r'(([a-f0-9:]+:+)+[a-f0-9]+)')
        find_ipv6 = re.findall(ipv6_pattern, string)
        # print(find_ipv6)
        for elem in find_ipv6:
            if len(elem[0]) > threshold_value:
                ipv6 = list(filter(lambda x : len(x)>threshold_value ,elem))[0] 
                if is_valid_ip_address(ipv6):
                    result.append(ipv6)
                else:
                    error_list.append(ipv6)
        if return_error:
            return result, error_list
        return result
    else:
        return ValueError("the input is not a string")
    
def is_private(IPAddress):
    """
    是否是私有地址
    """
    vaild_ip = ipaddress.ip_address(IPAddress)
    if vaild_ip.is_private:
        if vaild_ip.is_private:
            return True
        else:
            return False
    return ValueError('IPAddress is not a valid IPv4 or IPv6 address')

def ip_puvlic(IPAddress):
    """
    是否是公共地址
    """
    vaild_ip = ipaddress.ip_address(IPAddress)
    if vaild_ip.is_private:
        vaild_private_ip = ipaddress.ip_address(IPAddress)
        if vaild_private_ip:
            return False
        else:
            return True
    return ValueError('IPAddress is not a valid IPv4 or IPv6 address')

if __name__ == '__main__':
    import os
    case_path = os.path.expanduser('~/mingyueguan_project/IPAddress_processing/ipv4casefile.txt')
    case_file = [re.sub(r"^[\w\s]",'',line).strip('\n').replace("'",'').replace(",",'') for line in open(case_path, 'r').readlines()]
    for ipv4 in case_file:
        print(ipv4,is_valid_ip_address(ipv4))
        