from distutils.log import error
import re
import ipaddress
import geoip2.database
from const_IPAddress import city_ip_databases
import pandas as pd
import json
import requests

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

def is_puvlic(IPAddress):
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



def get_location_from_geoip2(ip,dataset_path_of_city=city_ip_databases):
    '''
    本地数据库ip信息查询
    '''
    return_error = {"ip地址":{ip}
            ,"国家":{None}
            ,"省份":{None}
            ,"城市":{None}
            ,"纬度":{None}
            ,"经度":{None}}
    try:
        reader = geoip2.database.Reader(dataset_path_of_city)
        ip_object = reader.city(ip)
        #print(ip_object)
        if ip_object == None:
            return return_error
        return  {"ip地址":ip_object.traits.ip_address
    ,"国家":ip_object.country.names
    ,"省份":ip_object.subdivisions.most_specific.names
    ,"城市":ip_object.city.names
    ,"纬度":ip_object.location.latitude
    ,"经度":ip_object.location.longitude}
    except Exception:
        return return_error
        
def change_language_logic(info):
    '''
    本地数据库ip信息查询的语言选择逻辑
    '''
    if 'zh-CN' in info:
        return info['zh-CN']
    elif 'en' in info:
        return info['en']
    elif 'es' in info:
        return info['es']
    elif 'fr' in info:
        return info['fr']
    elif 'de' in info:
        return info['de']
    elif 'ru' in info:
        return info['ru']
    elif 'ja' in info:
        return info['ja']
    elif 'pt-BR' in info:
        return info['pt-BR']
    else:
        return None
    
    
def parse_ip_location_from_geoip2(ip):
    '''
    本地数据库ip信息查询
    '''
    if is_puvlic(ip):
        ip_infos = get_location_from_geoip2(ip)
        ipv4 = ip_infos['ip地址']
        init_countries = change_language_logic(ip_infos['国家'])
        init_provinces = change_language_logic(ip_infos["省份"])
        init_city = change_language_logic(ip_infos["城市"])
        latitude = ip_infos['纬度']
        longitude = ip_infos['经度']
        return {"IPAddress":ipv4,"Countries":init_countries,"Provinces":init_provinces
        ,"City":init_city,"Latitude":latitude,"Longitude":longitude}
    else:
        return ValueError("IPAddress is not a public address")

def PaserIPFromGeoIP2Batch(IPs:iter,return_error=False):
    '''
    本地数据库ip信息查询
    '''
    # type_of_IPs = type(IPs)
    if isinstance(IPs,(dict,set)):
        distinct =  IPs
    else:
        distinct = set(IPs)
    result = {
        "IPAddress":[]
        ,"Countries":[]
        ,"Provinces":[]
        ,"City":[]
        ,"Latitude":[]
        ,"Longitude":[]
    }
    error_dict = {}
    for ip in distinct:
        try:
            parse = parse_ip_location_from_geoip2(ip)
            result['IPAddress'].append(parse['IPAddress'])
            result['Countries'].append(parse['Countries'])
            result['Provinces'].append(parse['Provinces'])
            result['City'].append(parse['City'])
            result['Latitude'].append(parse['Latitude'])
            result['Longitude'].append(parse['Longitude'])
        except Exception as e:
            error_dict.update({ip:e}) 
            
    return_tb = pd.DataFrame(result)
    if return_error:
        return return_tb,error_dict
    return return_tb

import requests
import json

def TokenIPiters(ip_list:iter,batch=100):
    """
    分割ipv4的课迭代数据，分成每100个一组
    """
    return_dict = {}
    n = 0
    t = 0
    for ipv4 in ip_list:
        n += 1
        if n > batch:
            t += 1
            n = 0
        if t in return_dict:
            return_dict[t].append(ipv4)
        else:
            return_dict.update({t:[ipv4]})
    return return_dict


def QueryIPAPIBatchMaximum100(ip_list:list):
    """
    """
    if isinstance(ip_list,list):
        pass
    else:
        return ValueError("param must a list ,plecae check you input code")
    
    distinct_ips = list(set(ip_list))
    max_lenght = len(distinct_ips)
    if max_lenght > 100:
        return ValueError("The maximum number of IP addresses that can be processed is 100 ,\
                          \nHTTP 422 Unprocessable Entity")
    
    
    counter_dict = {ipv4:0 for ipv4 in distinct_ips}
    
    for ipv4 in ip_list:
        counter_dict[ipv4]+=1
    #print(counter_dict) 
        # 多ip查询
    url = 'http://ip-api.com/batch?'
    # 定义接收参数及语言，可不传
    param = {
        'fields':'status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query'
        ,'lang': 'zh-CN'
    }


    response = requests.post(url=url, params=param, json=distinct_ips)
    
    return_text = response.text
    #print(return_text)
    result_json = json.loads(return_text)

def ParseIPAPIBatch(result_json):
    
    message_dict = {"status":[],"message":[],"query":[]}
    status_dict = {
        'query':[],'status':[],'continent':[]
        ,'continentCode':[],'country':[],'countryCode':[]
        ,'region':[],'regionName':[],'city':[]
        ,'district':[],'zip':[],'lat':[],'lon':[]
        ,'timezone':[],'offset':[],'currency':[]
        ,'isp':[],'org':[],'as':[],'asname':[]
        ,'mobile':[],'proxy':[],'hosting':[]

    }
    
    for line in result_json:
        #print(line)
         # 查询不到ip地址数据的返回处理
        if "message" in line:
            for key,value in line.items():
                message_dict[key].append(value)  
         # 查询到ip地址数据的返回处理
        elif 'status' in line:
            for key,value in line.items():        
                status_dict[key].append(value)  
                           
    status_table = pd.DataFrame(status_dict)
    message_table = pd.DataFrame(message_dict)

    status_size = status_table.size
    message_size = message_table.size

    if (status_size != 0) and (message_size != 0):
        return status_table,message_table
    elif (status_size != 0) and (message_size == 0):
        return status_table
    elif (status_size == 0) and (message_size != 0):
        return message_table
    
#QueryIPFromAPIBatchMaximum100(ipv4_case_file[:100])


if __name__ == '__main__':
    import os
    case_path = os.path.expanduser('~/mingyueguan_project/IPAddress_processing/ipv4casefile.txt')
    case_file = [re.sub(r"^[\w\s]",'',line).strip('\n').replace("'",'').replace(",",'') for line in open(case_path, 'r').readlines()]
    # for ipv4 in case_file:
    #     try:
    #         print(ipv4,is_valid_ip_address(ipv4),parse_ip_location_from_geoip2(ipv4))
    #     except Exception as e:
    #         print(ipv4,is_valid_ip_address(ipv4),e)
    print(PaserIPFromGeoIP2Batch(case_file[:100]))
    print((case_file))

        