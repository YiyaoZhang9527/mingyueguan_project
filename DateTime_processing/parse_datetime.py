import re
import time
import datetime
from os.path import expanduser
from sys import path
from wsgiref.handlers import format_date_time
path.append(expanduser("~/mingyueguan_project"))
from Mumber_processing.chinese_to_numbers import cn_to_number

now =  datetime.datetime.now()
now_date = now.strftime("%Y-%m-%d")
print(now_date)

def is_number(uchar):
    """判断一个unicode是否是数字"""
    if uchar >= u'\u0030' and uchar<=u'\u0039':
            return True
    else:
            return False

def is_chinese(uchar):
    """判断一个unicode是否是汉字"""
    if uchar >= u'\u4e00' and uchar<=u'\u9fa5':
            return True
    else:
            return False
    
def is_alphabet(uchar):
    """判断一个unicode是否是英文字母"""
    if (uchar >= u'\u0041' and uchar<=u'\u005a') or (uchar >= u'\u0061' and uchar<=u'\u007a'):
            return True
    else:
            return False

def is_other(uchar):
    """判断是否非汉字，数字和英文字符"""
    if not (is_chinese(uchar) or is_number(uchar) or is_alphabet(uchar)):
            return True
    else:
            return False
        
def is_symbol(uchar):
    """判断是否非汉字，数字和英文字符"""
    pattern = re.compile(r"[^\w\s]+")
    if pattern.match(uchar):
        return True
    else:
        return False

def count_char(string):
    '''
    中英文混合的字符串分类计数
    '''
    counter = {"alpha":0, "number":0
               , "chinese":0, "other":0
               , "symbol":0}
    
    for char in string:
        alpha = is_alphabet(char)
        number = is_number(char)
        chinese = is_chinese(char)
        symbol = is_symbol(char)
        other = is_other(char)
        if alpha:
            counter["alpha"] += 1
        elif number:
            counter["number"] += 1
        elif chinese:
            counter["chinese"] += 1
        elif symbol:
            counter["symbol"] += 1
        elif other:
            counter["other"] += 1
    return counter

def check_is_int(element):
    """
    判断是否是整数
    """
    if type(element) == str:
        if element.isdigit():
            return True
        else:
            try:
                int(element)
                return True
            except:
                return False
    elif type(element) == int:
        return True
    else:
        return False

print("check_is_int : ",check_is_int('-2080'))

def char_to_int(element):
    """
    将number字符转换为整数
    """
    if check_is_int(element):
        return int(element)
    else:
        return False

def seconds_to_time(seconds):
    """
    将秒数转换为时间格式
    """
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    return str(hours) + ":" + str(minutes) + ":" + str(seconds)

def seconds_to_datetime(seconds):
    """
    将秒数转换为时间格式
    """
    return datetime.datetime.fromtimestamp(seconds).strftime('%Y-%m-%d %H:%M:%S')



def format_en_datetime_MDH(linux_last_datetime):
    """
    将linux last / lastb 命令显示的 时间戳转换为英文时间格式
    example: Mon Mar 1 00:00
    """
    MDHM_to_seconds = time.mktime(time.strptime(linux_last_datetime, "%a %b %d %H:%M"))
    print(seconds_to_datetime(format_date_time))

def format_last_datetime(linux_last_datetime):
    """
    将linux last / lastb 命令显示的 时间戳转换为时间间格式
    example: Mon Mar 1
    """
    month_day_to_seconds = time.mktime(time.strptime(linux_last_datetime, "%a %b %d"))
    return seconds_to_datetime(month_day_to_seconds).split(' ')[0].replace("1900-",'')

"""
指令(Directive)
％a - 缩写的工作日名称

％A - 完整的工作日名称

％b - 缩写的月份名称

％B - 完整月份名称

％c - 首选日期和时间表示

％C - 世纪数（年份除以100，范围00至99）

％d - 月中的某天（01至31）

％D - 与％m /％d /％y相同

％e - 每月的日期（1到31）

％g - 像％G，但没有世纪

％G - 与ISO周数对应的4位数年份（参见％V）。

％h - 与％b相同

％H - 小时，使用24小时制（00至23）

％I - 小时，使用12小时制（01至12）

％j - 一年中的某一天（001至366）

％m - 月（01至12）

％M - 分钟

％n - 换行符

％p - 根据给定的时间值，am或pm

％r - 上午和下午表示法的时间

％R - 24小时表示法的时间

％S - 秒

％t - 制表符

％T - 当前时间，等于％H:％M:％S

％u - 工作日作为数字（1到7），星期一= 1。 警告:在Sun Solaris Sunday = 1中

％U - 当前年份的周数，从第一个星期日开始，作为第一周的第一天

％V - 当前年份的ISO 8601周数（01至53），其中第1周是当前年度至少有4天的第一周，周一是本周的第一天

％W - 当前年份的周数，从第一个星期一开始，作为第一周的第一天

％w - 星期几作为小数，星期日= 0

％x - 没有时间的首选日期表示

％X - 没有日期的首选时间表示

％y - 没有世纪的年份（范围00到99）

％Y - 包括世纪的年份

％Z或％z - 时区或名称或缩写

%% - 文字％字符
"""


if __name__ == "__main__":

    case = ["2020-01-01","2020/01/01","2020|01|01","2020.01.01","2020-1-1","2020/1/1","2020|1|1","2020.1.1",20000101,200011,"20000101","200011","2020年1月1"
    ,"二零零一年一月一日","二零零一年一月一日 十二点时十二分十二秒","二零零一年一月一日 十二点时十二分十二秒十二毫秒","二零零一年一月一日十二点时十二分十二秒十二毫秒","二零零一年一月一日十二点时十二分十二秒十二毫秒"
    ,"2020-01-01 12:12:12","2020年01月01日 12时12分12秒12毫秒","2020-01-01 12:12:12:12:12","Sat Mar 28 22:24:24 2016"]

    # # 格式化成2016-03-20 11:45:39形式
    # print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    
    # # 格式化成Sat Mar 28 22:24:24 2016形式
    # print(time.strftime("%a %b %d %H:%M:%S %Y", time.localtime()))
    
    # # 将格式字符串转换为时间戳
    # EN_datetime = "Sat Mar 28 22:24:24 2016"
    # linux_last_datetime = "Wed Jun  1 04:17"
    # linux_last_datetime = "Wed Jun  1"
    # print(format_last_datetime(linux_last_datetime))



    # EN_datetime_to_seconds = time.mktime(time.strptime(EN_datetime,"%a %b %d %H:%M:%S %Y"))
    # seconds_to_datetime(EN_datetime_to_seconds)
    # print("seconds_to_datetime:",seconds_to_datetime(EN_datetime_to_seconds))
    # # print('datetime.timedelta(seconds=b)',datetime.timedelta(seconds=EN_datetime_to_seconds))
    # # print("time.strftime(\"%H:%M:%S\", time.localtime(b))",time.strftime("%H:%M:%S", time.localtime(EN_datetime_to_seconds)))
    # from dateutil.parser import parse
 
    # t_list1 = ["202105271354", "202105272300"]
    # t_list2 = [210527050, 202105271148]
    
    # for t in t_list1:
    #     print(parse(t))
    

    
    # for t in t_list1:
    #     print(parse(str(t)))    # 先把数字日期转换成字符串格式

    # print(now_date)
    # print(now.strftime("%H:%M:%S"))
    # print(now.strftime("%H:%M"))
    # print(now.strftime("%H"))
    # print(now.strftime("%M"))
    # print(now.strftime("%S"))
    # print(now.strftime("%Y"))
    # print(now.strftime("%m"))
    # print(now.strftime("%d"))
    # print(now.strftime("%H:%M:%S"))syhi
    # print(now.strftime("%Y-%m-%d"))
    # print(now.strftime("%Y-%m-%d %H:%M:%S"))
    # print(now.strftime("%Y-%m-%d %H:%M"))
    # print(now.strftime("%Y-%m-%d %H"))
    # print(now.strftime("%Y-%m-%d %M"))
    # print(now.strftime("%Y-%m-%d %S"))
    # print(now.strftime("%Y-%m-%d %H:%M:%S"))
    # print(now.strftime("%Y-%m-%d %H:%M"))
    # print(now.strftime("%Y-%m-%d %H"))
    # print(now.strftime("%Y-%m-%d %M"))
    # print(now.strftime("%Y-%m-%d %S"))
    # print(now.strftime("%Y-%m-%d %H:%M:%S"))
    # print(now.strftime("%Y-%m-%d %H:%M"))
    pass