
import re

def regex_find_chinese_mobile_phone(text):

    """
    正则表达式匹配中国手机号码
    参考资料 : https://wenku.baidu.com/view/3020b817346baf1ffc4ffe4733687e21ae45ff4d.html
    :param text:
    :return:
    """
    all_pattern = r'(?:(?:\+?86)|(?:\(+86\)))?1[345789][0-9]{9}'
    
    # 中国移动手机号码
    CMCC_pattern = "1(?:34[0-8]|3[5-9]\d|5[0-2,7-9]\d|7[28]\d|8[2-4,7-8]\d|9[5,7,8]\d)\d{7}"
    # 中国联通手机号码
    QUCC_pattern = "1(?:3[0-2]|[578][56]|66|96)\d{8}"
    # 中国电信手机号码
    CTCC_pattern = "^1(?:33|53|7[37]|8[019]|9[0139])\d{8}$"
    # 中国广电手机号码
    CBN_pattern = "1(?:92)\d{8}"

    ## 虚拟运营商手机卡
    # 中国移动虚拟运营商手机卡
    virtual_pattern_CMCC = "1(?:70[356]|65\d)\d{7}"
    # 中国联通虚拟运营商手机卡
    virtual_pattern_QUCC = "1(?:70[4,7-9]|71\d|67\d)\d{7}"
    # 中国电信虚拟运营商手机卡
    virtual_pattern_CTCC = "1(?:70[0-2]|62\d)\d{7}$"

    # 全部虚拟运营商手机卡
    all_virtuall_patten = "1(?:70[356]|65\d|70[4,7-9]|71\d|67\d|70[0-2]|62\d)\d{7}"

    # 全部中国大陆手机号码
    all_chinese_mobile_pthone = "1(?:34[0-8]|3[5-9]\d|5[0-2,7-9]\d|7[28]\d|8[2-4,7-8]\d|9[5,7,8]\d|3[0-2]\d|[578]56]\d|66\d|96\d|33\d|53\d|7[37]\d|8[019]\d|9[0139]\d|92\d|70[356]|65\d|70[4,7-9]|71\d|67\d|70[0-2]|62\d)\d{7}"

    # 物联网数据卡 13位
    # 中国移动号段 1440,148
    CMC_Lot_data_card_pattern = "14(?:40|8\d)\d{9}"
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

    # 中国香港手机号码 未检查
    HK_pattern = "(?:(?:\+?852\-?)?[456789]\d{3}\-?\d{4}|(?:\(?\+852\)?\s?\d{3}\s?\d{4})|(?:\+852\s?\d{2}\s?\d{4}))"
    
    return re.findall(Maritime_Satellite_Communication_patter,text)

# import re
s1='wo ai ni ,nibu zai wo13322299223' \
   '我去14324565943 ewrwe,,' \
   ' 11344335632q' \
   'iiiwo13559923456' \
   'ewrw14333333333ewr'\
       'dhask86-19922445567hkas'

s2 = "13412345678 13512345678 150123456788 13312345678\
        13012345678 13112345678 13212345678 19216812345\
            13012345678 13312345678 13012345678 19316812345\
             17400010111  17406910101 17410111111 17499999111 "


print(regex_find_chinese_mobile_phone(s2))