from re import findall, VERBOSE,compile,sub

from sympy import im
from  const_IDCard import province_dict,various_regions_dict,city_dict,now,only_city_dict
from os import path,getcwd
from os.path import expanduser
from sys import path as sys_path
sys_path.append(expanduser("~/mingyueguan_project"))
from DateTime_processing.date_class import get_age
city_and_county_error_log_path = path.expanduser("~/mingyueguan_project/IDCard_processing/get_city_and_county_function_error_log.csv")
city_error_log_path = path.expanduser("~/mingyueguan_project/IDCard_processing/get_city_function_error_log.csv")

def varify_lenght_of_IDCard(IDCard):
    """
    中文注释 : 验证身份证号码长度
    英文注释 : Verify the length of IDCard
    """
    if type(IDCard) == int:
        IDCard = str(IDCard)
    else:
        pass

    if len(IDCard) == 18:
        return True
    else:
        return False

def varify_char_for_IDCard(IDCard):
    """
    中文注释 : 验证身份证中的字符是否合法
    英文注释 : verify char for IDCard
    """
    IDCard_char , char_range = set(list(IDCard)),{"0","1","2","3","4","5","6","7","8","9","X","x"}
    if IDCard_char <= char_range:
        return True
    else:
        return False

def varify_check_code(IDCard):
    """
    中文注释 : 验证身份证的验证码真伪
    英文注释 : verify check code
    """
    if varify_lenght_of_IDCard(IDCard) == False:
        return False    # 身份证号码长度不正确
    elif varify_char_for_IDCard(IDCard) == False:
        return False    # 身份证号码中包含非法字符
    else:
        coefficient = [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]
        remainder  = {0: 1,
                1: 0,
                2: "x",
                3: 9,
                4: 8,
                5: 7,
                6: 6,
                7: 5,
                8: 4,
                9: 3,
                10: 2}
        sum_ = 0
        end_char = IDCard[-1].lower()
        for i in range(17):
            char = IDCard[i]
            if char not in '0123456789':
                return False
            sum_ += int(char)*coefficient[i]
        quotient = sum_ % 11
        lab = remainder[quotient]
        if str(lab) == end_char:
            return True
        else:
            return False
        # sum_value = 0
        # coefficient = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        # check_code = [1, 0, 'X', 9, 8, 7, 6, 5, 4, 3, 2]
        # for i in range(18):
        #     if i <= 16:
        #         sum_value += int(IDCard[i])*coefficient[i]
        # vaild_value = check_code[sum_value % 11]
        # end_number = IDCard[-1]
        # if end_number == "X" or end_number == "x":
        #     end_number = 10
        # end_number = int(end_number)
        # if end_number==vaild_value:
        #     return True
        # else:
        #     return False


def get_birthday(IDCard):
    """
    中文注释 : 提取身份证中的出生日期
    英文注释 : get birthday from the IDCard
    """
    if varify_lenght_of_IDCard(IDCard):
        return IDCard[6:14]


def get_birthday_year(IDCard):
    """
    中文注释 : 提取身份证中的出生年份
    英文注释 : get birthday year
    """
    if varify_lenght_of_IDCard(IDCard):
        return IDCard[6:10]


def get_birthday_month(IDCard):
    """
    中文注释 : 提取身份证中的出生月份
    英文注释 : get birthday month
    """
    if varify_lenght_of_IDCard(IDCard):
        return IDCard[10:12]


def get_birthday_date(IDCard):
    """
    中文注释 : 提取身份证中的出生日期
    英文注释 : get birthday date
    """
    if varify_lenght_of_IDCard(IDCard):
        return IDCard[12:14]


def get_gender(IDCard):
    """
    中文注释 : 提取身份证中的性别信息
    英文注释 : get gender
    
    """
    if varify_lenght_of_IDCard(IDCard):
        index_17 = int(IDCard[16]) 
        mod = index_17 %2 
        parity = mod == 0
        if parity  :
            return {"zh-cn":"女","en-us":"female"}#,'code':parity}
        else:
            return {"zh-cn":"男","en-us":"male"}#,'code':parity}

    return False

    
def get_various_regions(IDCard):
    '''
    中文注释 : 提取身份证中的大区信息
    英文注释 : 
    '''
    if varify_lenght_of_IDCard(IDCard):
        index_1 = IDCard[0]
        if index_1 == "4":
            index_2 = IDCard[1]
            No4_dict =  various_regions_dict['4']
            for No,info in No4_dict.items():
                if index_2 in No :
                    return {"zh-cn":info}
        elif index_1 in various_regions_dict:
            return {"zh-cn":various_regions_dict[index_1]}
        return False
    return False



def get_province(IDCard):
    """
    中文注释 : 提取身份证中的省份信息
    英文注释 : 
    """
    if varify_lenght_of_IDCard(IDCard): 
        index_1_to_2 = IDCard[:2]
        if index_1_to_2 in province_dict:
            return {"zh-cn":province_dict[index_1_to_2]}
    return False

def get_city(IDCard):
    """
    中文注释 : 提取身份证中的城市信息
    
    """
    if varify_lenght_of_IDCard(IDCard):
        index_1_to_6 = IDCard[:6]
        if index_1_to_6 in only_city_dict:
            city = only_city_dict[index_1_to_6]
            return {"zh-cn":city}
        elif index_1_to_6 not in city_dict:
            with open(city_error_log_path,"a") as f:
                f.write('"'+index_1_to_6+'" : None \n')
            f.close()
            return False
        return False
    return False
                
            
def get_city_and_county(IDCard):
    """
    中文注释 : 提取身份证中的城市和乡镇信息
    英文注释 : 
    """
    
    pattern = compile(
    """
    (北京市)|(天津市)|(河北省)
    |(山西省)|(内蒙古自治区)|(辽宁省)
    |(吉林省)|(黑龙江省)|(上海市)
    |(江苏省)|(浙江省)|(安徽省)
    |(福建省)|(江西省)|(山东省)
    |(河南省)|(湖北省)|(湖南省)
    |(广东省)|(广西壮族自治区)|(海南省)
    |(重庆市)|(四川省)|(贵州省)
    |(云南省)|(西藏自治区)|(陕西省)
    |(甘肃省)|(青海省)|(宁夏回族自治区)
    |(新疆维吾尔自治区)|(台湾省)|(香港特别行政区)
    |(澳门特别行政区)
    """
    ,VERBOSE)

    if varify_lenght_of_IDCard(IDCard):
        index_1_to_6 = IDCard[:6]
        if index_1_to_6 in city_dict:
            complete_address = city_dict[index_1_to_6]
            return {"zh-cn":sub(pattern,'',complete_address)}
        elif index_1_to_6 not in city_dict:
            # 将为查询到的地区编码写入日志文件 后续更新
            with open(city_and_county_error_log_path,"a+") as f:
                f.write('"'+index_1_to_6+'" : None \n')
            f.close()
            return False
        return False
    return False


def get_prefecture_level_administrative_region(IDCard):
    """
    中文注释 : 提取地级行政区分类信息
    """
    if varify_lenght_of_IDCard(IDCard):
        index_3_to_4 = IDCard[2:4]
        index_1_to_2 = IDCard[:2]
        int_code = int(index_3_to_4)
        if int(index_1_to_2) in (11,12,31,50):
            if int_code == 1:
                return {"zh-cn":"直辖市市辖区"}
            elif int_code == 2:
                return {"zh-cn":"直辖市县区"}
        elif int_code in range(1,21):
            return {"zh-cn":"地级市"}
        elif int_code in range(21,51):
            return {"zh-cn":"地区、自治州、盟"}
        elif int_code in range(51,71):
            return {"zh-cn":"地级市"}
        elif int_code == 90 :
            return {"zh-cn":"省直辖县级行政单位"}
    return False


def get_county_level_administrative_region(IDCard):
    """
    中文注释 : 提取县级行政区分类信息
    """
    if varify_lenght_of_IDCard(IDCard):
        index_5_to_6 = IDCard[4:6]
        int_code = int(index_5_to_6)
        if int_code in range(1,19):
            return {"zh-cn":"市辖区或地区、自治州、盟辖县级市"}
        elif int_code in range(21,81):
            return {"zh-cn":"县、旗"}
        elif int_code in range(81,100):
            return {"zh-cn":"省直辖县级行政单位"}
    return False


def get_serial_number(IDCard):
    """
    中文注释 : 提取身份证中的序列号
    英文注释 : 
    """
    if varify_lenght_of_IDCard(IDCard):
        index_15_to_17 = IDCard[14:17]
        return {"zh-cn":index_15_to_17}
    return False


def regex_find_IDCard(text):
    """
    中文注释 : 提取所有中国身份证号码
    英文注释 : Extract all China IDCard numbers
    """

    pattern = compile(r"""(
                            # TODO 地区码为4位 

                            #地区码纯6位数字验证规则
                            #[1-9]\d{5}

                            # 地区码粗略规则
                                # ([1-6]|8\d{0}) # 地区码第一位表示大区
                                # (?:[1-9]\d{1,4}) # 地区码 后 3 位数字

                            # 地区码详细规则
                            (


                                1
                                    (?:(1|2|3|4|5)
                                    [0-9]{4}) # 华北地区
                                |
                                2
                                    (?:(1|2|3)
                                    [0-9]{4})
                                |
                                3
                                    (?:(1|2|3|4|5|6|7)
                                    [0-9]{4})
                                |
                                4
                                    (?:(1|2|3|4|5|6)
                                    [0-9]{4})
                                |
                                5
                                    (?:(0|1|2|3|4)
                                    [0-9]{4})
                                |
                                6
                                    (?:(1|2|3|4|5)
                                    [0-9]{4})
                                |
                                8
                                    (?:(1|2|3)
                                    [0-9]{4})
                            )


                            # TODO 年份
                            (?:
                                18|19|(?:[23]\d) # 年份前 2 位数字 1800开始到2399结束
                                ) 

                            \d{2} # 年份后 2 位数字

                            # TODO 月份   
                            (?:
                                (?:0[1-9]) # 1到 9 月 前置补 0
                                |  # 或的关系
                                (?:10|11|12)# 10、11、12 月
                            ) 
                            # TODO 日期
                            (?:
                                (?:[0-2][1-9]) # 日期第一位数字为 0-2 第二位数字为 1-9
                                |10|20|30|31 # 补充 10 ，20 ，30，31 号
                            )  
                            # TODO 当地出生顺序码 和性别码
                            \d{3}
                            
                            # TODO 校验码
                            [0-9Xx]

                        )"""
                        , VERBOSE)
    



    return [string[0] for string in findall(pattern, text)]


'''
TODO 未完成的功能
'''
def varify_date(IDCard):
    """
    中文注释 : 验证身份证中的生日是否合法
    英文注释 : 
    """
    if varify_lenght_of_IDCard(IDCard):
        year = get_birthday_year(IDCard)
        month = get_birthday_month(IDCard)
        date = get_birthday_date(IDCard)
        
        
    return False

'''
TODO 未完成的功能
'''
def varify_IDCard(IDCard):
    """
    中文注释 : 验证身份证号码
    英文注释 : Verify IDCard number
    """
    if varify_check_code(IDCard):
        # 提取出生年月日
        birthday = get_birthday(IDCard)
        # 提取出生年份
        birthday_year = get_birthday_year(IDCard) 
        # 提取出生月份
        birthday_month = get_birthday_month(IDCard)
        # 提取出生日期
        birthday_date = get_birthday_date(IDCard)
        # 提取性别
        gender = get_gender(IDCard)
        # 提取大区信息
        various_regions = get_various_regions(IDCard)
        # 提取省级行政单位
        province = get_province(IDCard)
        # 提取市级行政单位
        city = get_city(IDCard)
        # 提取市乡镇级行政单位
        city_and_county = get_city_and_county(IDCard)
        # 提取地级行政单位说明
        prefecture_level_administrative_region = get_prefecture_level_administrative_region(IDCard)
        # 提取县级行区说明
        county_level_administrative_region = get_county_level_administrative_region(IDCard)
        # 提取出生地顺序码
        serial_number = get_serial_number(IDCard)
        # 校验码验证
        varify_code= varify_check_code(IDCard)

        if birthday == False:
            birthday = None
        if birthday_year == False:
            birthday_year = None
        if birthday_month == False:
            birthday_month = None
        if birthday_date == False:
            birthday_date = None
        if gender == False:
            gender = {"zh-cn":None,"en-us":None}
        if various_regions == False:
            various_regions = {"zh-cn":None}
        if province == False:
            province = {"zh-cn":None}
        if city == False:
            city = {"zh-cn":None}
        if city_and_county == False:
            city_and_county = {"zh-cn":None}
        if prefecture_level_administrative_region == False:
            prefecture_level_administrative_region = {"zh-cn":None}
        if county_level_administrative_region == False:
            county_level_administrative_region = {"zh-cn":None}
        if serial_number == False:
            serial_number = None
        if varify_code == False:
            varify_code = None
        

        return {"id_card":IDCard
                ,"birthday":birthday
                ,"birthday_year":birthday_year
                , "birthday_month":birthday_month
                , "birthday_date":birthday_date
                ,"gender":gender
                ,"various_regions":various_regions
                ,"province":province
                ,"city":city
                ,"city_and_county":city_and_county
                ,"prefecture_level_administrative_region":prefecture_level_administrative_region
                ,"county_level_administrative_region":county_level_administrative_region
                ,"serial_number":serial_number
                ,"varify_code":varify_code
                ,"check_datetime":now}
        
        
    return False



def IDCardsInfo(IDCards:iter):
    result_dict = {
        'idCard':[]
        ,'birthday':[]
        ,"age":[]
        ,'birthday_year':[]
        ,'birthday_month':[]
        ,'birthday_date':[]
        ,'gender_cn':[]
        ,'gender_en':[]
        ,'various_regions':[]
        ,'province':[]
        ,'city':[]
        ,"city_and_county":[]
        ,'prefecture_level_administrative_region':[]
        ,'county_level_administrative_region':[]
        ,'serial_number':[]
        ,'varify_code':[]
        ,'check_datetime':[]

    }

    error_dict = {"error_IDCard":[]}

    for idCard in IDCards:

        IDCard_info = varify_IDCard(idCard)

        if IDCard_info:
            idCard = IDCard_info["id_card"]
            birthday = IDCard_info['birthday']
            age = get_age(birthday)
            birthday_year = IDCard_info["birthday_year"]
            birthday_month = IDCard_info["birthday_month"]
            birthday_date = IDCard_info["birthday_date"]
            gender_dict = IDCard_info["gender"]
            gender_cn = gender_dict["zh-cn"]
            gender_en = gender_dict["en-us"]
            various_regions = IDCard_info["various_regions"]["zh-cn"]
            province = IDCard_info["province"]["zh-cn"]
            city = IDCard_info["city"]["zh-cn"]
            city_and_county = IDCard_info["city_and_county"]["zh-cn"]
            prefecture_level_administrative_region = IDCard_info["prefecture_level_administrative_region"]["zh-cn"]
            county_level_administrative_region = IDCard_info["county_level_administrative_region"]["zh-cn"]
            serial_number = IDCard_info["serial_number"]["zh-cn"]
            varify_code = IDCard_info["varify_code"]
            datetime = IDCard_info["check_datetime"]


            result_dict['idCard'].append(idCard)
            result_dict['birthday'].append(birthday)
            result_dict["age"].append(age)
            result_dict['birthday_year'].append(birthday_year)
            result_dict['birthday_month'].append(birthday_month)
            result_dict['birthday_date'].append(birthday_date)
            result_dict['gender_cn'].append(gender_cn)
            result_dict['gender_en'].append(gender_en)
            result_dict['various_regions'].append(various_regions)
            result_dict['province'].append(province)
            result_dict['city'].append(city)
            result_dict['city_and_county'].append(city_and_county)
            result_dict['prefecture_level_administrative_region'].append(prefecture_level_administrative_region)
            result_dict['county_level_administrative_region'].append(county_level_administrative_region)
            result_dict['serial_number'].append(serial_number)
            result_dict['varify_code'].append(varify_code)
            result_dict['check_datetime'].append(datetime)

        else:
            error_dict["error_IDCard"].append(idCard)

    result_tb = pd.DataFrame(result_dict)
    result_tb.to_csv('CheckIDCardsResults.csv',index=False,encoding='utf-8',sep=',',mode='a+')#,header=False)

    error_tb = pd.DataFrame(error_dict)
    error_tb.to_csv('CheckIDCardsError.csv',index=False,encoding='utf-8',sep=',',mode='a+')#,header=False)

    return {"IDCrards_info_tables":result_tb,"error_idcards":error_tb}
        

if __name__ == "__main__":
    import pandas as pd
    path = path.expanduser("~/mingyueguan_project/IDCard_processing/IDCards_case_table.csv")
    IDCards = pd.read_csv(path).astype(str).IDCard.to_list()
    print(IDCardsInfo(IDCards))
    #print(varify_check_code("340402199603162448"))
    #print(varify_IDCard("34040219861102022X"))  
