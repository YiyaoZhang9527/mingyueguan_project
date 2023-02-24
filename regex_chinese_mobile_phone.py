from re import findall
#all_pattern = r'(?:(?:\+?86)|(?:\(+86\)))?1[345789][0-9]{9}'


def regex_find_CMCC(text):
    """
    中文注释 : 提取所有中国移动手机号码
    英文注释 : Extract all China Mobile Communications Group Co.,Ltd mobile phone numbers
    """
    # 中国移动手机号码
    CMCC_pattern = "1(?:34[0-8]|3[5-9]\d|5[0-2,7-9]\d|7[28]\d|8[2-4,7-8]\d|9[5,7,8]\d)\d{7}"
    return findall(CMCC_pattern, text)

def regex_find_QUCC(text):
    """
    中文注释 : 提取所有中国联通手机号码
    英文注释 : Extract all China Unicom mobile phone numbers
    """
    # 中国联通手机号码
    QUCC_pattern = "1(?:3[0-2]|[578][56]|66|96)\d{8}"
    return findall(QUCC_pattern, text)


def regex_find_CTCC(text):
    """
    中文注释 : 提取所有中国电信手机号码
    英文注释 : Extract all China Telecom mobile phone numbers
    """
    # 中国电信手机号码

    CTCC_pattern = "^1(?:33|53|7[37]|8[019]|9[0139])\d{8}$"
    return findall(CTCC_pattern, text)

def regex_find_CBN(text):
    """
    中文注释 : 提取所有中国广电手机号码
    英文注释 : Extract all China Broadcasting Network Corporation Ltd mobile phone numbers
    """
    # 中国广电手机号码
    CBN_pattern = "1(?:92)\d{8}"
    return findall(CBN_pattern, text)

## TODO 虚拟运营商手机卡

def regex_find_virtual_CMCC(text):
    """
    中文注释 : 提取所有中国移动虚拟手机号码
    英文注释 : Extract all China Mobile Communications Group Co.,Ltd virtual mobile phone numbers
    """
    # 中国移动虚拟手机号码
    #virtual_CMCC_pattern = "^1(?:3[0-9]|4[57]|5[0-35-9]|7[0-9]|8[0-9])\d{8}$"
    # 中国移动虚拟运营商手机卡
    virtual_CMCC_pattern = "1(?:70[356]|65\d)\d{7}"
    return findall(virtual_CMCC_pattern, text)

def regex_find_virtual_QUCC(text):
    """
    中文注释 : 提取所有中国联通虚拟手机号码
    英文注释 : Extract all China Unicom virtual mobile phone numbers
    """
    # 中国联通虚拟手机号码
    # virtual_QUCC_pattern = "1(?:3[0-2]|[578][56]|66|96)\d{8}"
    # 中国联通虚拟运营商手机卡
    virtual_QUCC_pattern  = "1(?:70[4,7-9]|71\d|67\d)\d{7}"
    return findall(virtual_QUCC_pattern, text)

def regex_find_virtual_CTCC(text):
    """
    中文注释 : 提取所有中国电信虚拟手机号码
    英文注释 : Extract all China Telecom virtual mobile phone numbers
    """
    # 中国电信虚拟手机号码
    # 中国电信虚拟运营商手机卡
    # virtual_CTCC_pattern = "1(?:70[356]|71\d|67\d)\d{7}"
    # 中国电信虚拟运营商手机卡
    virtual_CTCC_pattern = "1(?:70[0-2]|62\d)\d{7}$"
    return findall(virtual_CTCC_pattern, text)


def regex_find_all_virtual_phone(text):
    """
    中文注释 : 提取所有中国移动、联通、电信、广电虚拟手机号码
    英文注释 : Extract all China Mobile Communications Group Co.,Ltd virtual mobile phone numbers
    """
    # 中国移动、联通、电信、广电虚拟手机号码
    # all_virtual_phone_pattern = "1(?:3[0-2]|[578][56]|66|96)\d{8}|1(?:70[356]|71\d|67\d)\d{7}|1(?:70[4,7-9]|71\d|67\d)\d{7}|1(?:70[0-2]|62\d)\d{7}|1(?:92)\d{8}"
    # 全部虚拟运营商手机卡
    all_virtual_phone_pattern = "1(?:70[356]|65\d|70[4,7-9]|71\d|67\d|70[0-2]|62\d)\d{7}"
    return findall(all_virtual_phone_pattern, text)


def all_chine_phone_number(text):
    """
    中文注释 : 提取所有中国移动、联通、电信、广电手机号码
    英文注释 : Extract all China mobile phone numbers
    """
    # 中国移动、联通、电信、广电手机号码
    # all_phone_number_pattern = "1(?:3[0-2]|[578][56]|66|96)\d{8}|1(?:70[356]|71\d|67\d)\d{7}|1(?:70[4,7-9]|71\d|67\d)\d{7}|1(?:70[0-2]|62\d)\d{7}|1(?:92)\d{8}"
    # 全部中国大陆手机号码
    all_phone_number_pattern = "1(?:34[0-8]|3[5-9]\d|5[0-2,7-9]\d|7[28]\d|8[2-4,7-8]\d|9[5,7,8]\d|3[0-2]\d|[578]56]\d|66\d|96\d|33\d|53\d|7[37]\d|8[019]\d|9[0139]\d|92\d|70[356]|65\d|70[4,7-9]|71\d|67\d|70[0-2]|62\d)\d{7}"

    return findall(all_phone_number_pattern, text)

# TODO 物联网数据卡 13位

def regex_CMCC_Lot_data_card(text):
    """
    中文注释 : 提取所有 中国移动号段 物联网数据卡号码
    英文注释 : Extract all China Mobile Communications Group Co.,Ltd Lot data card numbers
    https://www.sohu.com/a/408870872_100194686
    """
    # 中国移动号段 10648、10647、1440、147、148、1849、178、172
    CMCC_Lot_data_card_pattern = "14(?:40|8\d)\d{9}" # 13位非语音号段支持短信无线数据通信
    # CMCC_Lot_data_card_pattern_call = "1(?:47[64-66]\d|84[90-99]\d|78[92-94]|72[40-45]\d)\d{7}"
    # if findall(CMCC_Lot_data_card_pattern_no_call, text):
    #     print("find: 1")
    #     return findall(CMCC_Lot_data_card_pattern_no_call, text)
    # else:
    #     print("find 2")
    return findall(CMCC_Lot_data_card_pattern, text)

testcase_for__CMCCLot = regex_CMCC_Lot_data_card("144001901100900901064798989898 \
    1723455678990065414878000088888914800980897899144089800000009172897961565009890\
        14774998769012")
for No in testcase_for__CMCCLot:
    print(No,len(No))

def regex_QUCC_Lot_data_card(text):
    """
    中文注释 : 提取所有 中国联通号段 物联网数据卡号码
    英文注释 : Extract all China Unicom Lot data card numbers
    """
    # 中国联通号段 130,131,132,155,156,185,186,145,176,175,170,171,173,174,177,178,182,183,184,187,188,147,172,199
    # QUCC_Lot_data_card_pattern = "1(?:3[0-2]|5[56]|7[7-9]|8[7-8]|9[7-9])\d{8}"
    # 中国联通号段 1400 146
    QUCC_Lot_data_card_pattern = "14(?:00|6\d)\d{9}"
    return findall(QUCC_Lot_data_card_pattern, text)


# 中国联通号段 1400 146
QUCC_Lot_data_card_pattern = "14(?:00|6\d)\d{9}"
# 中国电信号段 14010
CTCC_Lot_data_card_pattern = "14(?:10)\d{9}"

# 上网数据卡 11位
# 中国移动号段
CMC_Internet_data_card_pattern = "1(?:47)\d{8}"
# 中国联通号段
QUCC_Internet_data_card_pattern = "1(?:45)\d{8}"
# 中国电信号段
CTCC_Internet_data_card_pattern = "1(?:49)\d{8}"

# 卫星移动通信卡 11位
# 中国移动号段
CMC_Satellite_mobile_card_communication_pattern = "1(?:349)\d{7}"
# 中国电信号段
CTCC_Satellite_mobile_card_communication_pattern = "1(?:740[0-5])\d{6}"

# 工信部应急通信卡 1740 1741 
MIIT_Crisis_Communication_patten = "174(?:0[6-9]|1[0-2])\d{6}"

# 海事卫星通信卡 1749
Maritime_Satellite_Communication_patter = '1(?:749)\d{7}'
