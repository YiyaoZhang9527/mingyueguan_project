import re
from typing import List, Tuple ,Dict
import jieba
from collections import OrderedDict

# result = {}
# for i in s.splitlines():
#     temp_split = i.split("：")
#     temp_unicode =temp_split[0]
#     help = temp_split[-1]
#     temp_split_code = temp_unicode.split("-")
#     if len(temp_split_code) >= 2:
#         head,end = str(temp_split_code[0]),str(temp_split_code[1])
#         unicode = "".join(['r"[',"\\u",head,"-","\\u",end,']+"'])
#         result.update({help:unicode})
# print(result)

# for i,j in result.items():
#     print(",'"+i+"'",":",j)

regex_char_patterns_dict = {
    '阿拉伯数字/数字 (numbers/humber)':'"[\u0030-\u0039]"',
    
    "英文字母/字母 (letters/letter)":r"[a-zA-Z]+",
    "英文字母小写/字母小写 (lowercase letters)":r"[a-z]+",
    "英文字母大写/字母大写 (uppercase letters)":r"[A-Z]+",
    "符号集/符号 (symbols)":r"[^\w\s]+",

    'unicode 基本汉字 / 中文 / 简体字 (unicode basic Chinese chars)':r"[\u4E00-\u9FA5]+",
    "unicode 基本汉字补充 / 中文 / 简体字 (unicode basic Chinese chars supplement)":r"[\u9FA6-\u9FFF]+",
    "汉字扩展 A (unicode Chinese char extension B)":r"[\u3400-\u4DBF]+",

    'C0控制符及基本拉丁文 (C0 Control and Basic Latin)' : r"[\u0000-\u007F]+"
    ,'C1控制符及拉丁文补充-1 (C1 Control and Latin 1 Supplement) ' : r"[\u0080-\u00FF]+"
    ,'拉丁文扩展-A (Latin Extended-A) ' : r"[\u0100-\u017F]+"
    ,'拉丁文扩展-B (Latin Extended-B) ' : r"[\u0180-\u024F]+"
    ,'国际音标扩展 (IPA Extensions) ' : r"[\u0250-\u02AF]+"
    ,'空白修饰字母 (Spacing Modifiers) ' : r"[\u02B0-\u02FF]+"
    ,'结合用读音符号 (Combining Diacritics Marks) ' : r"[\u0300-\u036F]+"
    ,'希腊文及科普特文 (Greek and Coptic) ' : r"[\u0370-\u03FF]+"
    ,'西里尔字母 (Cyrillic) ' : r"[\u0400-\u04FF]+"
    ,'西里尔字母补充 (Cyrillic Supplement) ' : r"[\u0500-\u052F]+"
    ,'亚美尼亚语 (Armenian) ' : r"[\u0530-\u058F]+"
    ,'希伯来文 (Hebrew) ' : r"[\u0590-\u05FF]+"
    ,'阿拉伯文 (Arabic) ' : r"[\u0600-\u06FF]+"
    ,'叙利亚文 (Syriac) ' : r"[\u0700-\u074F]+"
    ,'阿拉伯文补充 (Arabic Supplement) ' : r"[\u0750-\u077F]+"
    ,'马尔代夫语 (Thaana) ' : r"[\u0780-\u07BF]+"
    ,'西非書面語言 (N\'Ko) ' : r"[\u07C0-\u077F]+"
    ,'阿维斯塔语及巴列维语 (Avestan and Pahlavi) ' : r"[\u0800-\u085F]+"
    ,'Mandaic ' : r"[\u0860-\u087F]+"
    ,'撒马利亚语 (Samaritan) ' : r"[\u0880-\u08AF]+"
    ,'天城文书 (Devanagari) ' : r"[\u0900-\u097F]+"
    ,'孟加拉语 (Bengali) ' : r"[\u0980-\u09FF]+"
    ,'锡克教文 (Gurmukhi) ' : r"[\u0A00-\u0A7F]+"
    ,'古吉拉特文 (Gujarati) ' : r"[\u0A80-\u0AFF]+"
    ,'奥里亚文 (Oriya) ' : r"[\u0B00-\u0B7F]+"
    ,'泰米尔文 (Tamil) ' : r"[\u0B80-\u0BFF]+"
    ,'泰卢固文 (Telugu) ' : r"[\u0C00-\u0C7F]+"
    ,'卡纳达文 (Kannada) ' : r"[\u0C80-\u0CFF]+"
    ,'德拉维族语 (Malayalam) ' : r"[\u0D00-\u0D7F]+"
    ,'僧伽罗语 (Sinhala) ' : r"[\u0D80-\u0DFF]+"
    ,'泰文 (Thai) ' : r"[\u0E00-\u0E7F]+"
    ,'老挝文 (Lao) ' : r"[\u0E80-\u0EFF]+"
    ,'藏文 (Tibetan) ' : r"[\u0F00-\u0FFF]+"
    ,'缅甸语 (Myanmar) ' : r"[\u1000-\u109F]+"
    ,'格鲁吉亚语 (Georgian) ' : r"[\u10A0-\u10FF]+"
    ,'朝鲜文 (Hangul Jamo) ' : r"[\u1100-\u11FF]+"
    ,'埃塞俄比亚语 (Ethiopic) ' : r"[\u1200-\u137F]+"
    ,'埃塞俄比亚语补充 (Ethiopic Supplement) ' : r"[\u1380-\u139F]+"
    ,'切罗基语 (Cherokee) ' : r"[\u13A0-\u13FF]+"
    ,'统一加拿大土著语音节 (Unified Canadian Aboriginal Syllabics) ' : r"[\u1400-\u167F]+"
    ,'欧甘字母 (Ogham) ' : r"[\u1680-\u169F]+"
    ,'如尼文 (Runic) ' : r"[\u16A0-\u16FF]+"
    ,'塔加拉语 (Tagalog) ' : r"[\u1700-\u171F]+"
    ,'Hanunóo ' : r"[\u1720-\u173F]+"
    ,'Buhid ' : r"[\u1740-\u175F]+"
    ,'Tagbanwa ' : r"[\u1760-\u177F]+"
    ,'高棉语 (Khmer) ' : r"[\u1780-\u17FF]+"
    ,'蒙古文 (Mongolian) ' : r"[\u1800-\u18AF]+"
    ,'Cham ' : r"[\u18B0-\u18FF]+"
    ,'Limbu ' : r"[\u1900-\u194F]+"
    ,'德宏泰语 (Tai Le) ' : r"[\u1950-\u197F]+"
    ,'新傣仂语 (New Tai Lue) ' : r"[\u1980-\u19DF]+"
    ,'高棉语记号 (Kmer Symbols) ' : r"[\u19E0-\u19FF]+"
    ,'Buginese ' : r"[\u1A00-\u1A1F]+"
    ,'Batak ' : r"[\u1A20-\u1A5F]+"
    ,'Lanna ' : r"[\u1A80-\u1AEF]+"
    ,'巴厘语 (Balinese) ' : r"[\u1B00-\u1B7F]+"
    ,'巽他语 (Sundanese) ' : r"[\u1B80-\u1BB0]+"
    ,'Pahawh Hmong ' : r"[\u1BC0-\u1BFF]+"
    ,'雷布查语(Lepcha) ' : r"[\u1C00-\u1C4F]+"
    ,'Ol Chiki ' : r"[\u1C50-\u1C7F]+"
    ,'曼尼普尔语 (Meithei/Manipuri) ' : r"[\u1C80-\u1CDF]+"
    ,'语音学扩展 (Phonetic Extensions) ' : r"[\u1D00-\u1D7F]+"
    ,'语音学扩展补充 (Phonetic Extensions Supplement) ' : r"[\u1D80-\u1DBF]+"
    ,'结合用读音符号补充 (Combining Diacritics Marks Supplement) ' : r"[\u1DC0-\u1DFF]+"
    ,'拉丁文扩充附加 (Latin Extended Additional) ' : r"[\u1E00-\u1EFF]+"
    ,'希腊语扩充 (Greek Extended) ' : r"[\u1F00-\u1FFF]+"
    ,'常 (General Punctuation) ' : r"[\u2000-\u206F]+"
    ,'上标及下标 (Superscripts and Subscripts) ' : r"[\u2070-\u209F]+"
    ,'货币符号 (Currency Symbols) ' : r"[\u20A0-\u20CF]+"
    ,'组合用记号 (Combining Diacritics Marks for Symbols) ' : r"[\u20D0-\u20FF]+"
    ,'字母式符号 (Letterlike Symbols) ' : r"[\u2100-\u214F]+"
    ,'数字形式 (Number Form) ' : r"[\u2150-\u218F]+"
    ,'箭头 (Arrows) ' : r"[\u2190-\u21FF]+"
    ,'数学运算符 (Mathematical Operator) ' : r"[\u2200-\u22FF]+"
    ,'杂项工业符号 (Miscellaneous Technical) ' : r"[\u2300-\u23FF]+"
    ,'控制图片 (Control Pictures) ' : r"[\u2400-\u243F]+"
    ,'光学识别符 (Optical char Recognition) ' : r"[\u2440-\u245F]+"
    ,'封闭式字母数字 (Enclosed Alphanumerics) ' : r"[\u2460-\u24FF]+"
    ,'制表符 (Box Drawing) ' : r"[\u2500-\u257F]+"
    ,'方块元素 (Block Element) ' : r"[\u2580-\u259F]+"
    ,'几何图形 (Geometric Shapes) ' : r"[\u25A0-\u25FF]+"
    ,'杂项符号 (Miscellaneous Symbols) ' : r"[\u2600-\u26FF]+"
    ,'印刷符号 (Dingbats) ' : r"[\u2700-\u27BF]+"
    ,'杂项数学符号-A (Miscellaneous Mathematical Symbols-A) ' : r"[\u27C0-\u27EF]+"
    ,'追加箭头-A (Supplemental Arrows-A) ' : r"[\u27F0-\u27FF]+"
    ,'盲文点字模型 (Braille Patterns) ' : r"[\u2800-\u28FF]+"
    ,'追加箭头-B (Supplemental Arrows-B) ' : r"[\u2900-\u297F]+"
    ,'杂项数学符号-B (Miscellaneous Mathematical Symbols-B) ' : r"[\u2980-\u29FF]+"
    ,'追加数学运算符 (Supplemental Mathematical Operator) ' : r"[\u2A00-\u2AFF]+"
    ,'杂项符号和箭头 (Miscellaneous Symbols and Arrows) ' : r"[\u2B00-\u2BFF]+"
    ,'格拉哥里字母 (Glagolitic) ' : r"[\u2C00-\u2C5F]+"
    ,'拉丁文扩展-C (Latin Extended-C) ' : r"[\u2C60-\u2C7F]+"
    ,'古埃及语 (Coptic) ' : r"[\u2C80-\u2CFF]+"
    ,'格鲁吉亚语补充 (Georgian Supplement) ' : r"[\u2D00-\u2D2F]+"
    ,'提非纳文 (Tifinagh) ' : r"[\u2D30-\u2D7F]+"
    ,'埃塞俄比亚语扩展 (Ethiopic Extended) ' : r"[\u2D80-\u2DDF]+"
    ,'追 (Supplemental Punctuation) ' : r"[\u2E00-\u2E7F]+"
    ,'CJK 部首补充 (CJK Radicals Supplement) ' : r"[\u2E80-\u2EFF]+"
    ,'康熙字典部首 (Kangxi Radicals) ' : r"[\u2F00-\u2FDF]+"
    ,'表意文字描述符 (Ideographic Description chars) ' : r"[\u2FF0-\u2FFF]+"
    ,'CJK 符号 (CJK Symbols and Punctuation) ' : r"[\u3000-\u303F]+"
    ,'日文平假名 (Hiragana) ' : r"[\u3040-\u309F]+"
    ,'日文片假名 (Katakana) ' : r"[\u30A0-\u30FF]+"
    ,'注音字母 (Bopomofo) ' : r"[\u3100-\u312F]+"
    ,'朝鲜文兼容字母 (Hangul Compatibility Jamo) ' : r"[\u3130-\u318F]+"
    ,'象形字注释标志 (Kanbun) ' : r"[\u3190-\u319F]+"
    ,'注音字母扩展 (Bopomofo Extended) ' : r"[\u31A0-\u31BF]+"
    ,'CJK 笔画 (CJK Strokes) ' : r"[\u31C0-\u31EF]+"
    ,'日文片假名语音扩展 (Katakana Phonetic Extensions) ' : r"[\u31F0-\u31FF]+"
    ,'封闭式 CJK 文字和月份 (Enclosed CJK Letters and Months) ' : r"[\u3200-\u32FF]+"
    ,'CJK 兼容 (CJK Compatibility) ' : r"[\u3300-\u33FF]+"
    ,'CJK 统一表意符号扩展 A (CJK Unified Ideographs Extension A) ' : r"[\u3400-\u4DBF]+"
    ,'易经六十四卦符号 (Yijing Hexagrams Symbols) ' : r"[\u4DC0-\u4DFF]+"
    ,'CJK 统一表意符号 (CJK Unified Ideographs) ' : r"[\u4E00-\u9FBF]+"
    ,'彝文音节 (Yi Syllables) ' : r"[\uA000-\uA48F]+"
    ,'彝文字根 (Yi Radicals) ' : r"[\uA490-\uA4CF]+"
    ,'Vai ' : r"[\uA500-\uA61F]+"
    ,'统一加拿大土著语音节补充 (Unified Canadian Aboriginal Syllabics Supplement) ' : r"[\uA660-\uA6FF]+"
    ,'声调修饰字母 (Modifier Tone Letters) ' : r"[\uA700-\uA71F]+"
    ,'拉丁文扩展-D (Latin Extended-D) ' : r"[\uA720-\uA7FF]+"
    ,'Syloti Nagri ' : r"[\uA800-\uA82F]+"
    ,'八思巴字 (Phags-pa) ' : r"[\uA840-\uA87F]+"
    ,'Saurashtra ' : r"[\uA880-\uA8DF]+"
    ,'爪哇语 (Javanese) ' : r"[\uA900-\uA97F]+"
    ,'Chakma ' : r"[\uA980-\uA9DF]+"
    ,'Varang Kshiti ' : r"[\uAA00-\uAA3F]+"
    ,'Sorang Sompeng ' : r"[\uAA40-\uAA6F]+"
    ,'Newari ' : r"[\uAA80-\uAADF]+"
    ,'越南傣语 (Vi?t Thái) ' : r"[\uAB00-\uAB5F]+"
    ,'Kayah Li ' : r"[\uAB80-\uABA0]+"
    ,'朝鲜文音节 (Hangul Syllables) ' : r"[\uAC00-\uD7AF]+"
    ,'High-half zone of UTF-16 ' : r"[\uD800-\uDBFF]+"
    ,'Low-half zone of UTF-16 ' : r"[\uDC00-\uDFFF]+"
    ,'自行使用區域 (Private Use Zone) ' : r"[\uE000-\uF8FF]+"
    ,'CJK 兼容象形文字 (CJK Compatibility Ideographs) ' : r"[\uF900-\uFAFF]+"
    ,'字母表達形式 (Alphabetic Presentation Form) ' : r"[\uFB00-\uFB4F]+"
    ,'阿拉伯表達形式A (Arabic Presentation Form-A) ' : r"[\uFB50-\uFDFF]+"
    ,'变量选择符 (Variation Selector) ' : r"[\uFE00-\uFE0F]+"
    ,'竖排形式 (Vertical Forms) ' : r"[\uFE10-\uFE1F]+"
    ,'组合用半符号 (Combining Half Marks) ' : r"[\uFE20-\uFE2F]+"
    ,'CJK 兼容形式 (CJK Compatibility Forms) ' : r"[\uFE30-\uFE4F]+"
    ,'小型变体形式 (Small Form Variants) ' : r"[\uFE50-\uFE6F]+"
    ,'阿拉伯表達形式B (Arabic Presentation Form-B) ' : r"[\uFE70-\uFEFF]+"
    ,'半型及全型形式 (Halfwidth and Fullwidth Form) ' : r"[\uFF00-\uFFEF]+"
    ,'特殊 (Specials)' : r"[\uFFF0-\uFFFF]+"

}

# natural language regex_function generation patterns
def regex_expression_rule_selection(types_of_language:list):
    """
    generate natural language regex_function from types_of_language
    """
    return_regex_char_patterns_list = [] 
    for language_lab in types_of_language:
        for lab in regex_char_patterns_dict:
            if language_lab in lab:
                if language_lab in lab:
                    regex_string = regex_char_patterns_dict[lab]
                    list_of_char = ['s', 'a', 'i','\\','"',"'",'+']
                    pattern_of_regex_string = ''.join(list_of_char)
                    # Remove chars matched by pattern
                    pattern_char = re.sub(pattern_of_regex_string, '', regex_string)
                    return_regex_char_patterns_list.append("|"+pattern_char)

    print(return_regex_char_patterns_list)
    return "".join(list(OrderedDict.fromkeys(return_regex_char_patterns_list)))


def regex_find_language(text:str, types_of_language:list):
    """
    find language from text
    """
    regex_string = regex_expression_rule_selection(types_of_language)
    
    pattern = "re.findall(r'"+regex_string[1:]+"',text)"
    print("code of pattern:",pattern)
    return eval(pattern) 
                


#print(language_lab)
        
text = "This is a sample string 1 这是一个简单的字符串 ，123，【】[],"        
print(regex_find_language(text,["中文","英文","符号","数字"]))


# Regex checks whether it is Chinese
