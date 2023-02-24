from email import message
import re
from urllib.parse import urlparse
from urllib.request import urlopen
from sys import path
from os.path import expanduser

path.append(expanduser("~/mingyueguan_project"))

# from Regular_extraction_class.what_language_is_it import what_language_is_it



def valid_url_with_regex1(url):
       
    """ 
    url参数: 是一个字符串，表示一个url地址
    param url: url to be parsed
    
    中文注释 ： 用正则表达式检查url是否是有效的的方法1
    English comment: check the url is valid or not with regex method 1
    """
    # URL-link validation
    ip_middle_octet = u"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5]))"
    ip_last_octet = u"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))"
    URL_PATTERN = re.compile(
                            u"^"
                            # protocol identifier
                            u"(?:(?:https?|ftp|rtsp|rtp|mmp)://)"
                            # user:pass authentication
                            u"(?:\S+(?::\S*)?@)?"
                            u"(?:"
                            u"(?P<private_ip>"
                            # IP address exclusion
                            # private & local networks
                            u"(?:localhost)|"
                            u"(?:(?:10|127)" + ip_middle_octet + u"{2}" + ip_last_octet + u")|"
                            u"(?:(?:169\.254|192\.168)" + ip_middle_octet + ip_last_octet + u")|"
                            u"(?:172\.(?:1[6-9]|2\d|3[0-1])" + ip_middle_octet + ip_last_octet + u"))"
                            u"|"
                            # IP address dotted notation octets
                            # excludes loopback network 0.0.0.0
                            # excludes reserved space >= 224.0.0.0
                            # excludes network & broadcast addresses
                            # (first & last IP address of each class)
                            u"(?P<public_ip>"
                            u"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])"
                            u"" + ip_middle_octet + u"{2}"
                            u"" + ip_last_octet + u")"
                            u"|"
                            # host name
                            u"(?:(?:[a-z\u00a1-\uffff0-9_-]-?)*[a-z\u00a1-\uffff0-9_-]+)"
                            # domain name
                            u"(?:\.(?:[a-z\u00a1-\uffff0-9_-]-?)*[a-z\u00a1-\uffff0-9_-]+)*"
                            # TLD identifier
                            u"(?:\.(?:[a-z\u00a1-\uffff]{2,}))"
                            u")"
                            # port number
                            u"(?::\d{2,5})?"
                            # resource path
                            u"(?:/\S*)?"
                            # query string
                            u"(?:\?\S*)?"
                            u"$",
                            re.UNICODE | re.IGNORECASE
                        )                                                                                                                                                      
    return re.compile(URL_PATTERN).match(url) is not None


def valid_url_with_regex2(url):
    """
    url参数: 是一个字符串，表示一个url地址
    param url: url to be parsed
    
    中文注释 ： 用正则表达式检查url是否是有效的的方法2
    English comment: check the url is valid or not with regex method 2
    """
    return bool( re.match(
        r"(https?|ftp)://" # protocol
        r"(\w+(\-\w+)*\.)?" # host (optional)
        r"((\w+(\-\w+)*)\.(\w+))" # domain
        r"(\.\w+)*" # top-level domain (optional, can have > 1)
        r"([\w\-\._\~/]*)*(?<!\.)" # path, params, anchors, etc. (optional)
    , url) )



def parsing_method_verify_url(url):#,
    min_attributes = ('scheme', 'netloc')
    """
    url参数: 是一个字符串，表示一个url地址
    param url: url to be parsed
    
    中文注释 ： 用urllib解析并检查url是否是有效的
    English comment: use urllib to parse and check the url is valid or not
    """
    tokens = urlparse(url)
    return all([getattr(tokens, qualifying_attr) 
            for qualifying_attr in min_attributes])


def valid_url_access(url):
    """
    中文注释 ： 检查url是否可以访问
    English comment: check a website is accessible or not
    """
    try:
        try_to_access = urlopen(url).getcode()
        if try_to_access == 200:
            return True
        return try_to_access
    except:
        return False


def parsed_score(url):
    '''
    url参数: 是一个字符串，表示一个url地址
    param url: url to be parsed
    
    中文注释 ： 投票方法得到url解析有效性的分数
    English comment: vote method to get the score of url parsing validity
    '''
    # if url is a valid url, then add it to the list
    # check url with vote percentage method
    valid_url_list = []
    if valid_url_with_regex1(url):
        valid_url_list.append(True)
    if valid_url_with_regex2(url):
        valid_url_list.append(True)
    if parsing_method_verify_url(url):
        valid_url_list.append(True)
    score = sum(valid_url_list)
    if score > 0:
        return score/len(valid_url_list)*100
    else:
        return False



# def display_message(params:dict):
#     '''
#     params参数: 是一个字典，表示一个参数字典
#     param params: params to be parsed
    
#     中文注释 ： 根据参数字典中的设置选择是否显示错误消息提示
#     English comment: select whether to display error message according to the setting in the params dictionary
#     '''
#     if "display_error_message" in params:
#         return params['display_error_message']
#     return False

def valid_url(url):
    """
    url参数：url地址
    error_message参数：是否显示错误信息
    display_language参数：显示语言，默认中文
    
    param url: url to be checked
    param error_message: if True, display error message
    param display_language: if True, display error message in chinese or english
    
    
    中文注释 ： 检查url是否可以访问
    English comment: check a website is accessible or not
    """
    try:
        if type(url) is not str:
            #if message_language_selection(message_language):

            print("Error : Url must be a string !!!")
            return False
        score = parsed_score(url)
        if score > 0:
   
            print(
                "{}{}{}".format(
                    "Character parsing to verify the validity of the url:\n"
                    ,score
                    ,"%"))
            if valid_url_access(url):

                print(
                        "{}{}".format(
                        "The url is valid and accessible:\n"
                        ,url))
                return True
            else:
                print("The url is valid but not accessible")
                return False
        else:
            print("Error: url string is not valid")
            return False
    except Exception as error:
        print(error)
        return False


case1 = "https://stackoverflow.com/questions/7160737/how-to-validate-a-url-in-python-malformed-or-not/55827638#55827638"
#case2 = "https://www.google.com/search?q=python+Verify+that+the+url+is+accessible&oq=python++Verify+that+the+url+is+accessible&ie=UTF-8"
##print(valid_url_with_regex1(case1))

#print(valid_url_with_regex2(case1))

#print(parsing_method_verify_url(case1))
print(valid_url(case1))

# import urllib
# try:
#     urllib.urlopen(case1)
# except IOError:
#     print("not a real url")
# print(valid_url(case1))
