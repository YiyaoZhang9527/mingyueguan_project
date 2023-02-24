from decimal import *

'https://blog.csdn.net/lly1122334/article/details/107004681#:~:text=%E9%BB%98%E8%AE%A4%E8%BD%AC%E6%8D%A2%E6%96%B9%E5%BC%8F%EF%BC%9A%20num%20%3D%20int,num3%20%3D%20int(hexadecimalString%2C16'

def chinese2digit(cn):
    '''中文转数字

    :param cn: 中文字符串
    :return: 数字
    >>> chinese2digit('十一')
    11
    >>> chinese2digit('九万八千零七十六点五四三二一')
    Decimal('98076.54321')
    '''
    CN_NUM = {
        '〇': 0, '一': 1, '二': 2, '三': 3, '四': 4, '五': 5, '六': 6, '七': 7, '八': 8, '九': 9,
        '零': 0, '壹': 1, '贰': 2, '叁': 3, '肆': 4, '伍': 5, '陆': 6, '柒': 7, '捌': 8, '玖': 9,
        '貮': 2, '两': 2
    }
    CN_UNIT = {
        '十': 10, '拾': 10, '百': 100, '佰': 100, '千': 1000, '仟': 1000, '万': 10000, '萬': 10000,
        '亿': 100000000, '億': 100000000, '兆': 1000000000000
    }

    cn = cn.split('点')
    integer = list(cn[0])  # 整数部分
    decimal = list(cn[1]) if len(cn) == 2 else []  # 小数部分
    unit = 0  # 当前单位
    parse = []  # 解析数组
    while integer:
        x = integer.pop()
        if x in CN_UNIT:
            # 当前字符是单位
            unit = CN_UNIT.get(x)
            if unit == 10000:
                parse.append('w')  # 万位
                unit = 1
            elif unit == 100000000:
                parse.append('y')  # 亿位
                unit = 1
            elif unit == 1000000000000:  # 兆位
                parse.append('z')
                unit = 1
            continue
        else:
            # 当前字符是数字
            dig = CN_NUM.get(x)
            if unit:
                dig = dig * unit
                unit = 0
            parse.append(dig)

    if unit == 10:  # 处理10-19的数字
        parse.append(10)

    result = 0
    tmp = 0
    while parse:
        x = parse.pop()
        if x == 'w':
            tmp *= 10000
            result += tmp
            tmp = 0
        elif x == 'y':
            tmp *= 100000000
            result += tmp
            tmp = 0
        elif x == 'z':
            tmp *= 1000000000000
            result += tmp
            tmp = 0
        else:
            tmp += x
    result += tmp

    if decimal:
        unit = 0.1
        getcontext().prec = len(decimal)  # 小数精度
        result = Decimal(float(result))
        tmp = Decimal(0)
        for x in decimal:
            dig = CN_NUM.get(x)
            tmp += Decimal(str(dig)) * Decimal(str(unit))
            unit *= 0.1
        getcontext().prec = len(result.to_eng_string()) + len(decimal)  # 完整精度
        result += tmp
    return result


def chinese_chr_to_number_char(chinese_char):
    """
    将中文日期转换为数字
    """
    dict_ = {
        '零':0,
        '一':1,
        '二':2,
        '三':3,
        '四':4,
        '五':5,
        '六':6,
        '七':7,
        '八':8,
        '九':9,
    }
    result = ''
    if type(chinese_char) == str:
        for char in chinese_char:
            if char in dict_.keys():
                result += str(dict_[char])
            else:
                return False
    return result

def cn_to_number(chinese_num):
    if set(list(chinese_num)) <=  {'零','一', '七', '三', '九', '二', '五', '八', '六', '四'}:
        return chinese_chr_to_number_char(chinese_num)
    elif ("十" in chinese_num)|("百" in chinese_num)|("千" in chinese_num)|("万" in chinese_num)|("亿" in chinese_num)|("兆" in chinese_num):
        return str(chinese2digit(chinese_num))
    else:
        print("Erro : function cn_to_number()")

# print("cn_to_number:",cn_to_number("二零零一"))
# print("chinese_chr_to_number_char('一二三四五六七八九')",chinese_chr_to_number_char('二零零一'))


if __name__ == '__main__':
    test = [
        '九',  # 9
        '十一',  # 11
        '一百二十三',  # 123
        '一千二百零三',  # 1203
        '一万一千一百零一',  # 11101
        '十万零三千六百零九',  # 103609
        '一百二十三万四千五百六十七',  # 1234567
        '一千一百二十三万四千五百六十七',  # 11234567
        '一亿一千一百二十三万四千五百六十七',  # 111234567
        '一百零二亿五千零一万零一千零三十八',  # 10250011038
        '一千一百一十一亿一千一百二十三万四千五百六十七',  # 111111234567
        '一兆一千一百一十一亿一千一百二十三万四千五百六十七',  # 1111111234567
        '九万八千零七十六点五四三二一零七四五六',  # 98076.54321
        '九万八千零七十六点五四三二一',  # 98076.54321
    ]

    for i in test:
        print(cn_to_number(i))
        print("\n")


'''
6月16日凌晨00:47更新注释：
'''
# from decimal import *

# 'https://blog.csdn.net/lly1122334/article/details/107004681#:~:text=%E9%BB%98%E8%AE%A4%E8%BD%AC%E6%8D%A2%E6%96%B9%E5%BC%8F%EF%BC%9A%20num%20%3D%20int,num3%20%3D%20int(hexadecimalString%2C16'

# def chinese2digit(cn):
#     '''中文转数字

#     :param cn: 中文字符串
#     :return: 数字
#     >>> chinese2digit('十一')
#     11
#     >>> chinese2digit('九万八千零七十六点五四三二一')
#     Decimal('98076.54321')
#     '''
#     CN_NUM = {
#         '〇': 0, '一': 1, '二': 2, '三': 3, '四': 4, '五': 5, '六': 6, '七': 7, '八': 8, '九': 9,
#         '零': 0, '壹': 1, '贰': 2, '叁': 3, '肆': 4, '伍': 5, '陆': 6, '柒': 7, '捌': 8, '玖': 9,
#         '貮': 2, '两': 2
#     }
#     CN_UNIT = {
#         '十': 10, '拾': 10, '百': 100, '佰': 100, '千': 1000, '仟': 1000, '万': 10000, '萬': 10000,
#         '亿': 100000000, '億': 100000000, '兆': 1000000000000
#     }

#     cn = cn.split('点')
#     integer = list(cn[0])  # 整数部分
#     decimal = list(cn[1]) if len(cn) == 2 else []  # 小数部分
#     unit = 0  # 当前单位
#     parse = []  # 解析数组
#     while integer:
#         x = integer.pop()
#         if x in CN_UNIT:
#             # 当前字符是单位
#             unit = CN_UNIT.get(x)
#             if unit == 10000:
#                 parse.append('w')  # 万位
#                 unit = 1
#             elif unit == 100000000:
#                 parse.append('y')  # 亿位
#                 unit = 1
#             elif unit == 1000000000000:  # 兆位
#                 parse.append('z')
#                 unit = 1
#             continue
#         else:
#             # 当前字符是数字
#             dig = CN_NUM.get(x)
#             if unit:
#                 dig = dig * unit
#                 unit = 0
#             parse.append(dig)

#     if unit == 10:  # 处理10-19的数字
#         parse.append(10)

#     result = 0
#     tmp = 0
#     while parse:
#         x = parse.pop()
#         if x == 'w':
#             tmp *= 10000
#             result += tmp
#             tmp = 0
#         elif x == 'y':
#             tmp *= 100000000
#             result += tmp
#             tmp = 0
#         elif x == 'z':
#             tmp *= 1000000000000
#             result += tmp
#             tmp = 0
#         else:
#             tmp += x
#     result += tmp

#     if decimal:
#         unit = 0.1
#         getcontext().prec = len(decimal)  # 小数精度
#         result = Decimal(float(result))
#         tmp = Decimal(0)
#         for x in decimal:
#             dig = CN_NUM.get(x)
#             tmp += Decimal(str(dig)) * Decimal(str(unit))
#             unit *= 0.1
#         getcontext().prec = len(result.to_eng_string()) + len(decimal)  # 完整精度
#         result += tmp
#     return result


# # def is_number(s):
# #     try:
# #         float(s)
# #         return True
# #     except ValueError:
# #         pass
 
# #     try:
# #         import unicodedata
# #         unicodedata.numeric(s)
# #         return True
# #     except (TypeError, ValueError):
# #         pass
 
# #     return False
 
 
# # def chinese2digit(cn):
# #     """中文转数字
# #     :param cn: 中文字符串
# #     :return: 数字
# #     >>> chinese2digit('十一')
# #     11
# #     >>> chinese2digit('九万八千零七十六点五四三二一')
# #     Decimal('98076.54321')
# #     """
# #     CN_NUM = {
# #         '〇': 0, '一': 1, '二': 2, '三': 3, '四': 4, '五': 5, '六': 6, '七': 7, '八': 8, '九': 9,
# #         '零': 0, '壹': 1, '贰': 2, '叁': 3, '肆': 4, '伍': 5, '陆': 6, '柒': 7, '捌': 8, '玖': 9,
# #         '貮': 2, '两': 2
# #     }
# #     CN_UNIT = {
# #         '十': 10, '拾': 10, '百': 100, '佰': 100, '千': 1000, '仟': 1000, '万': 10000, '萬': 10000,
# #         '亿': 100000000, '億': 100000000, '兆': 1000000000000
# #     }
 
# #     cn = cn.split('点')
# #     integer = list(cn[0])  # 整数部分
# #     decimal = list(cn[1]) if len(cn) == 2 else []  # 小数部分


# if __name__ == '__main__':
#     test = [
#         '九',  # 9
#         '十一',  # 11
#         '一百二十三',  # 123
#         '一千二百零三',  # 1203
#         '一万一千一百零一',  # 11101
#         '十万零三千六百零九',  # 103609
#         '一百二十三万四千五百六十七',  # 1234567
#         '一千一百二十三万四千五百六十七',  # 11234567
#         '一亿一千一百二十三万四千五百六十七',  # 111234567
#         '一百零二亿五千零一万零一千零三十八',  # 10250011038
#         '一千一百一十一亿一千一百二十三万四千五百六十七',  # 111111234567
#         '一兆一千一百一十一亿一千一百二十三万四千五百六十七',  # 1111111234567
#         '九万八千零七十六点五四三二一零七四五六',  # 98076.54321
#         '九万八千零七十六点五四三二一',  # 98076.54321
#     ]

#     for i in test:
#         print(chinese2digit(i))