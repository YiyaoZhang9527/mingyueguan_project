
import re
import time
import datetime
from os.path import expanduser
from sys import path
path.append(expanduser("~/mingyueguan_project"))
from Mumber_processing.chinese_to_numbers import cn_to_number

from DateTime_processing.const_datetime import en_week_table,en_month_table


now =  datetime.datetime.now()

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



def char_to_int(element):
    """
    将number字符转换为整数
    """
    if check_is_int(element):
        return int(element)
    else:
        return False

def parse_YMDHMS(time_string):
    """
    分割年月日时分秒的时间字符串
    """

    if check_is_int(time_string):
        time_string = char_to_int(time_string)
        if time_string >= 10000000000:
            time_string = str(time_string)
            year, month, day, hour, minute, second = time_string[:-10],time_string[-10:-8],time_string[-8:-6],time_string[-6:-4],time_string[-4:-2],time_string[-2:]
            return year, month, day, hour, minute, second
    elif type(time_string) == str:
        pass
    else:
        print("Error : [funtion name : parse_YMDHMS] \n  time must be a string or int or int and length is 14 or 16 or 17")
        return False
    
    split_by_chinese = re.split(r"[年月日时分秒|\s|^\W]+",time_string)
    split_by_symbol = re.split(r"[^\w]+",time_string)
    split_by_english = re.split(r"[a-zA-Z]+",time_string)
    length_cn,lenght_symbol,length_en= len(split_by_chinese),len(split_by_symbol), len(split_by_english)
    max_lenght = max(length_cn,lenght_symbol,length_en)
    result = {length_cn:split_by_chinese
    ,lenght_symbol:split_by_symbol
    ,length_en:split_by_english}[max_lenght]
    if "" in result:
        result.remove("")
    return tuple(result)



def parse_YMD(date_string):
    """
    解析字符串里的时间
    
    pattern: 年月日字符串
    renturn: 1.年月日元组 2.如果出现争议分割如2000111则优先分割为:(2000,11,1)除非月份超过12
    """
    
    if type(date_string) == str:
        pass
    elif type(date_string) == int:
        date_string = str(date_string)
    else:
        print("Error : [funtion name : parse_YMD ] \n date_string must be a string or int")
        return False
    counter = count_char(date_string)
    length = len(date_string)
    index_first = date_string[0] == '-'
    number , symbol , chinese , other , alpha = counter["number"] ,counter["symbol"],counter["chinese"],counter["other"],counter["alpha"]
    chinese_symbol = ('年' in date_string) and ('月' in date_string) and ('日' in date_string)
    # print("chinese_symbol",chinese_symbol,chinese)
    
    def temp_intersection(alpha_n=0,number_n=0,chinese_n=0,other_n=0,symbol_n=0):
        """
        判断是否有交集
        """
        if (alpha_n == alpha) | (number_n == number) | (chinese_n == chinese) | (other_n == other) | (symbol_n == symbol):
            return True
        else:
            return False
        
    def init_year_month_day(year,month,day):
        """
        初始化年月日缺位补0
        """
        length_year = len(year)
        length_month = len(month)
        length_day = len(day)
        if length_year < 4:
            init_year = (4-length_year)*"0"+year
        elif length_year == 4:
            init_year = year
        if length_month < 2:
            init_month = "0"+month
        elif length_month == 2:
            init_month = month
        if length_day < 2:
            init_day = "0"+day
        elif length_day == 2:
            init_day = day
        return init_year,init_month,init_day  
    if length == 6:
        if temp_intersection(number_n=6):
            year ,month,day = date_string[:4],date_string[5],date_string[5:]
            return init_year_month_day(year,month,day)
    elif  length == 7:
        if temp_intersection(number_n=7):
            '''
            简单判断，完全判断需要写完日期合法性判断函数
            '''
            year  = date_string[:4]
            month_1 = "0"+date_string[4:5]
            month_2 = date_string[4:6]
            day_1 = date_string[5:]
            day_2 = "0"+date_string[-1]
            if int(month_2) <=12 and int(day_2) <=31: # 如果月份小于12，并且天数小于31，则是8位的日期格式
                month,day = month_2,day_2
            elif int(month_1) <=12 and int(day_1 ) <=31: # 如果月份小于12，并且天数小于31，则是8位的日期格式
                month,day = month_1,day_1
            return {"优先分割月份":[init_year_month_day(year,month,day)]}   
    elif length == 8:
        if temp_intersection(number_n=8) and (index_first==False) :
            # print("9 length n=",number," ,s = ",symbol)
            year ,month,day = date_string[:4],date_string[4:6],date_string[6:]
            return init_year_month_day(year,month,day)
        elif temp_intersection(number_n=7,symbol_n=1) and index_first:
            # print("9 length n=",number," ,s = ",symbol)
            year  = date_string[1:5]
            month_1 = "0"+date_string[5:6]
            month_2 = date_string[5:7]
            day_1 = date_string[6:]
            day_2 = "0"+date_string[-1]
            '''
            简单判断，完全判断需要写完日期合法性判断函数
            '''
            if int(month_2) <=12 and int(day_2) <=31: # 如果月份小于12，并且天数小于31，则是8位的日期格式
                month,day = month_2,day_2
            elif int(month_1) <=12 and int(day_1 ) <=31: # 如果月份小于12，并且天数小于31，则是8位的日期格式
                month,day = month_1,day_1
            return {"优先分割月份":[init_year_month_day(year,month,day)]}
    elif (length == 9 ) and (chinese_symbol == False) :
        if temp_intersection(number_n=8,symbol_n=1) and index_first: # n=8 , s=1 
            # print("9 length n=",number," ,s = ",symbol)
            year , month ,day = date_string[1:5] , date_string[5:7] , date_string[7:]
            return '-'+year , month , day
        elif temp_intersection(number_n=7,symbol_n=2) :
            # print("9 length n=",number," ,s = ",symbol)
            year , month ,day = (elem for elem in re.split(r"[^\w\s]+",date_string) if elem != "") #date_string[:4] , "0"+date_string[5:6] , date_string[7:]
            return init_year_month_day(year , month , day)
    elif (length == 10) and (chinese_symbol == False):
        if temp_intersection(number_n=9,symbol_n=1) and index_first:
            # print("10 length n=",number," ,s = ",symbol)
            year , month ,day = date_string[1:6] , date_string[6:8] , date_string[8:]
            return '-'+year , month , day
        elif temp_intersection(number_n=8,symbol_n=2):
            # print("10 length n=",number," ,s = ",symbol)
            year , month , day = date_string[:4] , date_string[5:7] , date_string[8:]
            return year , month , day
    elif chinese == 3 and chinese_symbol :
        # print("chinese = ",chinese," ,chinese_symbol = ",chinese_symbol)
        year ,month ,day =  (elem for elem in re.split(r"[\u4E00-\u9FA5]",date_string) if elem  != '')
        return init_year_month_day(year , month , day)
    elif chinese <= 11 | chinese >=6 | chinese_symbol:
        # print("chinese = ",chinese," ,chinese_symbol = ",chinese_symbol)
        init_year ,init_month ,init_day =  (elem for elem in re.split(r"[年月日]+",date_string) if elem  != '')
        year ,month ,day =  cn_to_number(init_year) , cn_to_number(init_month) , cn_to_number(init_day)
        return init_year_month_day(year , month , day)
    else:
        print("Error : can't parse the string of the date")
        return False

            
def int_to_date(date):
    """
    年月日的数字转时间戳
    """
    if date >= 10000000000:
        date = str(date)
        year, month, day, hour, minute, second =date[:-10],date[-10:-8],date[-8:-6],date[-6:-4],date[-4:-2],date[-2:]
        return datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
    date_str = str(date)
    year ,month, day = parse_YMD(date_str)
    date = datetime.datetime(int(year), int(month), int(day))
    return date



def str_to_date(date):
    """
    年月日的字符串转时间戳
    """

    if check_is_int(date):
        return int_to_date(int(date))
    elif type(date) == str:
        try:
            year, month, day, hour, minute, second = parse_YMDHMS(date)
            date =  datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
            return date
        except Exception as erre:
            year,month,day = parse_YMD(date)   
            date =  datetime.datetime(int(year), int(month), int(day))
            return date
    else:
        print("Error : can't parse it please check the type of the date")
        return False




def init_date(date):
    """
    将日期整形转换为字符串
    """
    try:
        if type(date) == int:
            date_str = int_to_date(date)
            return date_str
        elif type(date) == str:
            date_str = str_to_date(date)
            return date_str
        else:
            print("Error : [funtion name : init_date ] \n  date must be a string or int")
            return  False
    except:
        return False



def date_to_mktime(date):
    """
    将日期转换为时间戳
    """
    init_date_string_to_time =  init_date(date)
    if init_date:
        return time.mktime(init_date_string_to_time.timetuple())
    else:
        print("Error : [funtion name : date_to_mktime ] \n date must be a string or int")
        return False




def valid_date_is_beyong_today(date):
    """
    检查日期是否超过今天
    """
    try:
        init_now = date_to_mktime(now_date)
        init_date = date_to_mktime(date)
        if init_now == init_date:
            return {"zh-cn":"就是今天","en":"today"}
        elif init_now > init_date:
            return True
        else:
            return False
    except Exception as error:
        print("Error : [funtion name : valid_date_is_beyong_today ] \n valid_date function error \n:",error)
        return False




def is_year(year):
    """
    判断是否是年份,因为年份必须是数字，所以用int()转换，转换不了的就会报错
    负数则为公元前的年份
    """
    if check_is_int(year):
        return True
    else:
        print("Error : [funtion name : is_year ] \n year must be a int or number char")
        return False





def is_leap_year(year):
    """
    判断是否是闰年
    """
    try:
        if is_year(year):
            int_year = int(year)
            year_number_is_divisible_by_100 = int_year % 100 == 0
            year_number_is_divisible_by_400 = int_year % 400 == 0
            year_number_is_divisible_by_4 = int_year % 4 == 0
            if (year_number_is_divisible_by_4) & (year_number_is_divisible_by_100 == False):
                return True
            elif year_number_is_divisible_by_400:
                return True
            else:
                # print("\nError : [funtion name : is_leap_year ] \n "
                #     ,"\nyear_number_is_divisible_by_100:",year_number_is_divisible_by_100
                #     ,"\nyear_number_is_divisible_by_400:",year_number_is_divisible_by_400
                #     ,"\nyear_number_is_divisible_by_4:",year_number_is_divisible_by_4)
                return False
        else:
            return False
    except Exception as error:
        print("Error : [funtion name : is_leap_year ] \n is_leap_year function error \n:",error)
        return False

def leap_year_list(start=1800,end=2035):
    """

    """
    return [i  for i in range(start,end) if is_leap_year(i)]


def count_differ_days(time_a, time_b):
        """
        计算⽇期相差天数
        """
        try:
            
            time_a ,time_b = init_date(time_a), init_date(time_b)
            # 因为得到的是UTC时间，所以需要UTC时间+8
            time_a = time_a + datetime.timedelta(hours=8)
            time_b = time_b + datetime.timedelta(hours=8)
            day1 = datetime.date(time_a.year, time_a.month, time_a.day)
            day2 = datetime.date(time_b.year, time_b.month, time_b.day)
            return (day1 - day2).days
        except Exception as error:
            print("Error : [funtion name : count_differ_days ] \n count_differ_days function error \n:",error)
            return False




def get_age(date):
    """
    计算年龄
    """
    try:
        if type(date) == int:
            date = int_to_date(date)
        elif type(date) == str:
            date = str_to_date(date)
        else:
            print("Error : [funtion name : get_age ] \n  date must be a string or int")
            return  False
        now_date = datetime.datetime.now()
        #print("now-date:",(now_date-date).year)
        age = now_date.year - date.year
        if now_date.month < date.month:
            age = age - 1
        elif now_date.month == date.month:
            if now_date.day < date.day:
                age = age - 1
        return age
    except:
        return False




def valid_date(date):
    """
    检查日期是否合法
    """
    if init_date(date):
        return init_date(date)
    else: 
        return parse_YMDHMS(date)
    

def is_month(string, month_table=en_month_table):
    # 英文月份转数字
    check_index = month_table == string
    vaild_month = check_index .to_numpy().sum()
    if vaild_month:
        return month_table.数字[check_index.sum(axis=1) > 0].values[0]
    
def is_week(string, week_table=en_week_table):
    # 英文星期转数字
    check_index = week_table == string
    vaild_week = check_index .to_numpy().sum()
    #m,n = check_index.shape
    #m_true,n_true = np.where(check_index.to_numpy()==True)
    if vaild_week:
        return week_table.数字[check_index.sum(axis=1) > 0].values[0]


if __name__ == "__main__":

    case = ["2020-01-01","2020/01/01","2020|01|01","2020.01.01","2020-1-1","2020/1/1","2020|1|1","2020.1.1",20000101,200011,"20000101","200011","2020年1月1"
    ,"二零零一年一月一日","二零零一年一月一日 十二点时十二分十二秒","二零零一年一月一日 十二点时十二分十二秒十二毫秒","二零零一年一月一日十二点时十二分十二秒十二毫秒","二零零一年一月一日十二点时十二分十二秒十二毫秒"
    ,"2020-01-01 12:12:12","2020年01月01日 12时12分12秒12毫秒","2020-01-01 12:12:12:12:12"]
    # print("parse_YMDHMS:",parse_YMDHMS("1999年02月11日 02时04分01秒"),parse_YMDHMS("20180605115959"))
    # print("parse_YMD:",parse_YMD("二零一八年十二月八日"))
    # print("int to date :",int_to_date(91204085059))
    # print("string to date :", str_to_date("19990211"),str_to_date("1999-02-11"))
    # print("init date from stings :",init_date("20180605115959"))
    # print("init date from int : ",init_date(19870521))
    # print("date to mkitime",date_to_mktime(19870521))
    # print("valid_date_is_beyong_today:",valid_date_is_beyong_today("20220615"))        
    # print("is year :",is_year("-2018"))
    # print("is leap year ：",is_leap_year(-12000))
    # print("count differ days :",count_differ_days("2016-05-06" ,"2016-04-06 20:28:54" ))
    # print("get_age:",get_age('1999年02月11日02时04分01秒'))    
    # print("valid_date:",valid_date("-999-02-11 00:00:00"))
    print("check_is_int : ",check_is_int('-2080'))
    now_date = now.strftime("%Y-%m-%d")
    print("now date",now_date)
    print([""])
    print("is_month:",is_month("Jun"))
    print("is_week:",is_week("Wed"))

 


        




    

# print(str(now).split())
# print(["0"+str(elem) if len(str(elem)) == 1 else elem for elem in time.localtime() ]) 

'''
6月16日凌晨00:47注释掉，以下内容已经修改
'''
# import time
# import datetime

# now =  datetime.datetime.now()

# now_date = now.strftime("%Y-%m-%d")
# print("now date",now_date)

# def split_date(date_str):
#     """
#     分割年月日的日期字符串
#     """
#     lenght = len(date_str)
#     if lenght == 8:
#         year = date_str[:4]
#         month = date_str[4:6]
#         day = date_str[6:]
#         return year, month, day
#     elif lenght == 10:
#         year = date_str[:4]
#         month = date_str[5:7]
#         day = date_str[8:]
#         return year, month, day
#     else:
#         return False
    
# print("split date :",split_date("2018-08-08"))

# def int_to_date(date_int):
#     """
#     年月日的数字转时间戳
#     """
#     date_str = str(date_int)
#     year ,month, day = split_date(date_str)
#     date = datetime.datetime(int(year), int(month), int(day))
#     return date

# print("int to date :",int_to_date(19080415))

# def str_to_date(date):
#     """
#     年月日的字符串转时间戳
#     """
#     year,month,day = split_date(date)   
#     return datetime.datetime(int(year), int(month), int(day))

# print("string to date :", str_to_date("2018-08-08"))


# def init_date_string(date):
#     """
#     将日期整形转换为字符串
#     """
#     try:
#         if type(date) == int:
#             date_str = int_to_date(date)
#             return date_str
#         elif type(date) == str:
#             date_str = str_to_date(date)
#             return date_str
#         else:
#             return "ERROR: date must be a string or int"
#     except:
#         return False
    
# print("init date from stings :",init_date_string("2018-08-08"))

# print("init date from int : ",init_date_string(19870521))

# def date_to_mktime(date):
#     """
#     将日期转换为时间戳
#     """
#     init_date =  init_date_string(date)
#     if init_date:
#         return time.mktime(init_date.timetuple())
#     else:
#         return False

# print("date to mkitime",date_to_mktime(19870521))

# def valid_date_is_beyong_today(date):
#     """
#     检查日期是否超过今天
#     """
#     try:
#         init_now = date_to_mktime(now_date)
#         return init_now > date_to_mktime(date)
#     except Exception as error:
#         print("Error : valid_date function error \n:",error)
#         return False

# def is_year(year):
#     """
#     判断是否是年份
#     """
#     if type(year) == int:
#         year = str(year)
#     if len(year) == 4:
#         for num in year:
#             if num not in ("0","1","2","3","4","5","6","7","8","9"):
#                 return False
#         return year
                
#     else:
#         return False

# print("is year :",is_year(1987))


# def is_leap_year(year):
#     """
#     判断是否是闰年
#     """
#     if is_year(year):
#         int_year = int(year)
#         year_number_is_divisible_by_100 = int_year % 100 == 0
#         year_number_is_divisible_by_400 = int_year % 400 == 0
#         year_number_is_divisible_by_4 = int_year % 4 == 0
#         if (year_number_is_divisible_by_4) & (year_number_is_divisible_by_100 == False):
#             return True
#         elif year_number_is_divisible_by_400:
#             return True
#         else:
#             return False
#             #return year_number_is_divisible_by_4 ,year_number_is_divisible_by_100,year_number_is_divisible_by_400
#     else:
#         return False

# print("is leap year ：",is_leap_year(2001))

# def check_date_table(date):
#     """

#     """
    

# def valid_date(date):
#     """
#     检查日期是否合法
#     """
#     pass

    
# print("valid_date:",valid_date(20220808))
    
    
    


# print(str_to_date("19870521"))

# print(str(now).split())
# print(["0"+str(elem) if len(str(elem)) == 1 else elem for elem in time.localtime() ]) 

