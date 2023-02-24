import re

# Regex checks whether it is Chinese, Japanese, or English

def extract_pure_chinese(text):
    '''
    提取纯中文 
    extract pure chinese
    '''
    return re.sub(r'[^\u4e00-\u9fff]',"", text)

print("function is_extract_pure_chinese:", extract_pure_chinese(".sdsada123123 中文"))

def contains_chinese(text):
    """
    判断是否含有中文
    Determine whether the string contains Chinese
    """
    return len(extract_pure_chinese(text)) != 0

def is_chinese_char(character):
    """
    判断是否为中文字符
    check whether it is chinese char
    """
    if len(character)  == 1:
        if character in range(0x4E00, 0x9FFF):
            return True
    else :
        return False
    
print("function name is 'is_chinese_char':",is_chinese_char("中文"))

def extract_pure_english(text):
    '''
    提取纯英文 
    extract pure english
    '''
    return re.sub(r'[^a-zA-Z]',"", text)

print(extract_pure_english("sjdklsajdklsaj 哈哈哈 111"))

def contains_english(text):
    """
    判断是否含有英文
    Determine whether the string contains English
    """
    return len(extract_pure_english(text)) != 0

def is_engelish_char(character):
    """
    判断是否为英文字符
    check whether it is english char
    """
    if character in range(0x0041, 0x005A) or character in range(0x0061, 0x007A):
        return True
    else :
        return False

def extract_pure_janapanese_hiragana_char(text):
    '''
    提取纯日文 
    日语 - 平假名 - 字符
    ひらがな
    extract pure japanese, hiragana, kana chars
    '''
    return re.sub(r'[^\u3040-\u3094\u309E\u309B\u309C\u30FC]',"", text)

def contains_japanese_hiragana_char(text):
    """
    判断是否含有日文平假名字符
    Determine whether the string contains japanese hiragana kana char
    """
    return len(extract_pure_janapanese_hiragana_char(text)) != 0

def extract_pure_japanese_katakana_char(text):
    """
    提取纯日文 
    日语 - 片假名 - 字符
    カタカナ
    """
    return re.sub(r'[^\u30A0-\u30FB\u30FD\u30FE\u309B\u309C\u30FC]',"", text)

def contains_japanese_katakana_char(text):
    """
    判断是否含有日文片假名字符
    Determine whether the string contains japanese katakana kana char
    """
    return len(extract_pure_japanese_katakana_char(text)) != 0

def extract_pure_japanese_Japanese_katana_phonetic(text):
    """
    提取纯日文 片假名 - 日语音标
    日语 - 片假名 - 日语音标
    """
    return re.sub(r'[^\u3099-\u309E]',"", text)

def contains_japanese_Japanese_katana_phonetic(text):
    """
    判断是否为日文片假名日语音标
    Determine whether the string contains japanese katakana kana phonetic
    """
    return len(extract_pure_japanese_Japanese_katana_phonetic(text)) != 0

def extract_pure_japanese_char(text):
    """
    提取纯日文 
    日语 - 字符
    """
    return re.sub(r'[^\u3040-\u309F\u30A0-\u30FF]',"", text)


contains_japanese_string = "is only japanese hiragana 只有日文平假名测验 毎週金曜［総合］後10:45ファミレス、空港、居酒屋…。毎回、一つの現場にカメラを据え、そこで起きるさまざまな人間模様を72時間にわたって定点観測するドキュメンタリー番組。偶然出会った人たちの話に耳を傾け、“今” という時代を切り取ります。"
print("是否含有中文检测:", contains_chinese("is only chinese 只有中文测验"))
print("是否含有英文检测:", contains_english("is only english 只有英文测验"))
print(extract_pure_janapanese_hiragana_char(contains_japanese_string))
print("是否含有日文检测:", contains_japanese_hiragana_char(contains_japanese_string))


