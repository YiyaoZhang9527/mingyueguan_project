import re

#from Regular_extraction_class.numbers import Regular_extraction_of_number

def regex_find_symbol(string):
    """
    Regular extraction of symbol.
    """
    return re.findall(r"[^\w\s]+", string)

def regex_find_chinese_char(string):
    """
    Regular extraction of Chinese.
    中文
    """
    return re.findall(r"[\u4E00-\u9FA5]+", string)

def regex_find_chinese_and_number_char(string):
    """
    Regular extraction of chinese and number.
    """
    return re.findall(r"[\u4e00-\u9fa5]+|[0-9]+", string)

def regex_find_chinese_and_english_char(string):
    """
    Regular extraction of chinese and english.
    """
    return re.findall(r"[\u4e00-\u9fa5]+|[a-zA-Z]+", string)

def regex_find_chinese_and_english_and_number(string):
    """
    Regular extraction of chinese and english and number.
    """
    return re.findall(r"[\u4e00-\u9fa5]+|[a-zA-Z0-9]+", string)


def regex_find_chinese_and_symbol_char(string):
    """
    Regular extraction of chinese and symbol.
    """
    return re.findall(r"[\u4e00-\u9fa5]+|[^\w\s]+", string)

#print(regex_find_chinese_and_number_char("print 'hello'中哦昂文字,;;;;11121"))

def regex_find_chinese_and_number_and_symbol(string):
    """
    Regular extraction of chinese and number and symbol.
    """
    return re.findall(r"[\u4e00-\u9fa5]+|[0-9]+|[^\w\s]+", string)

org_string = "This is a sample string 这是一个简单的字符串 ，123，【】[],"

print(regex_find_chinese_and_number_and_symbol(org_string))

#print("tage:",re.findall(r'[0-9]|[\u2150-\u218F]+|[\u2460-\u24FF]+|[\u0041-\u005A]|[\u0061-\u007A]|[\u0041-\u005A]|[\u0061-\u007A]',org_string))

def regex_find_findenglish(string):
    """
    Regular extraction of english.
    """
    return re.findall(r"[a-zA-Z]+", string)

def regex_find_english_and_number(string):
    """
    Regular extraction of english and number.
    """
    return re.findall(r"[a-zA-Z0-9]+", string)

def regex_find_english_lower(string):
    """
    Regular extraction of english lower.
    英语小写
    """
    return re.findall(r"[a-z]+", string)

def regex_find_english_capital(string):
    """
    Regular extraction of english capital.
    英语大写
    """
    return re.findall(r"[A-Z]+", string)

def regex_find_French_char(string):
    """
    Regular extraction of French.
    法语
    """
    return re.findall(r"[A-Za-z\u00C0-\u017F]+", string)

def regex_find_Korean_char(string):
    """
    Regular extraction of Korean.
    韩语
    """
    return re.findall(r"[가-힣]+", string)

def regex_find_Japanese_hiragana_char(string):
    """
    Regular extraction of Japanese.
    日语 - 平假名
    """
    return re.findall(r"[\u3040-\u3094\]+\u309E\u309B\u309C\u30FC", string)

def regex_find_Japanese_katakana_char(string):
    """
    Regular extraction of Japanese.
    日语 - 片假名
    """
    return re.findall(r"[\u30A0-\u30FB\u30FD\u30FE\u309B\u309C\u30FC]+", string)

def regex_find_Japanese_katakana_phonetic_extension(string):
    """
    Regular extraction of Japanese.
    日语 - 片假名 - 后缀
    """
    #return re.findall(r"[\u31F0-\u31FF]+", string)
    return re.findall["[ㇰㇱㇲㇳㇴㇵㇶㇷㇸㇹㇺㇻㇼㇽㇾㇿ]",string]

def regex_find_Japanese_kanji_char(string):
    """
    Regular extraction of Japanese.
    日语 - 汉字
    """
    return re.findall(r"[\u4E00-\u9FA5]+", string)

def regex_find_Japanese_char(string):
    """
    Regular extraction of Japanese.
    日语
    """
    return re.findall(r"[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FA5]+", string)

def regex_find_Russian_char(string):
    """
    Regular extraction of Russian.
    俄语 
    西里尔字母
    """
    return re.findall(r"[\u0400-\u04FF\u0500-\u052F]+", string)

def regex_find_Arabic_char(string):
    """
    Regular extraction of Arabic.

    阿拉伯语
    """
    return re.findall(r"[\u0600-\u06FF\u0750-\u077F]+", string)

def regex_find_Hebrew_char(string):
    """
    Regular extraction of Hebrew.
    希伯来语    
    """
    return re.findall(r"[\u0590-\u05FF]+", string) 

def regex_find_Syriac_char(string):
    """
    Regular extraction of Syriac.
    叙利亚语
    """
    return re.findall(r"[\u0700-\u074F]+", string)

def regex_find_Thaana_char(string):
    """
    Regular extraction of Thaana.
    阿拉伯语
    """
    return re.findall(r"[\u0780-\u07BF]+", string)

def regex_find_Nko_char(string):
    """
    Regular extraction of N'ko
    西非书面语
    """
    return re.findall(r"[\u07C0-\u07FF]+", string)

def regex_find_Avstan_and_Pahlavi_char(string):
    """
    Regular extraction of Avstan and Pahlavi.

    百度百科参考：

    阿维斯塔语和巴拉依语

    阿维斯塔语:阿维斯塔语是一种古老的印欧语系语言，属于伊朗语族的东伊朗语，
    亦是波斯古经《阿维斯塔》成书时所使用的语言。“阿维斯塔”一词与印度的“吠陀”
    相似，所以有语言学家认为这是伊朗语族与印度语族诸语相近的一个历史印证。

    阿维斯塔语现时一般被归入东伊朗语支。这种语言跟西伊朗语支语言间的一个
    重要差别，在于阿维斯塔语有很丰富的元音，而且它同时保存了颚音和咝音。
    部分语言学家认为是一种印欧语开始分化（即咝音化）的现象，可以看到原来
    古印欧语丰富的颚音已开始简化，并开始出现咝辅音。但亦有语言学家认为这
    其实表明东伊朗语族和西伊朗语族本来就是不同的语种，而西伊朗语族更应该
    被归入闪含语系，而不是印欧语系。对于这种现象，语言学家有不同的意见。
    这是因为东、西伊朗的分离，我们还未有较深入的认识；另一方面，亦由于阿
    维斯塔语并没有演化成今日语言中的其中一种，而昔日的文本亦已残破不砧，
    使我们难以把它与今日伊朗诸语作比较，使它的分类不确定。

    url:https://baike.baidu.com/item/%E9%98%BF%E7%BB%B4%E6%96%AF%E5%A1%94%E8%AF%AD/18184558

    wiki 参考：

    巴拉依语/巴列维文字
    （Pahlavi；Pahlavi scripts）是各类型中古伊朗语言的一种特殊的、
    专门的书面文字。巴列维文字本质上的特征为：使用特殊的阿拉米字母衍生
    之文字；用为阿拉米语异形词之词汇表现的文字（称为hozwārishn，"古语")。
    巴列维文字的作品已被发现用于安息语、中古波斯语、粟特语、斯基啡亚语言
    以及于阗语等之方言或民族语言。[3]如果使用独立于巴列维文字系统的变体
    形式，那该变体语言的书面形式只有在具有上述之特征时才能称为符合巴列维文字的特征条件。
    巴列维文字的综合特性则是
        帝国阿拉米语的书面文字；而巴列维文字、语标和一些词汇就是从这些
        书面文字中衍生出来的。
        中古伊朗语的口语白话；巴列维文字的词尾终止符、符号规则，以及大部
        分的词汇都源自于此。
    因此，巴列维文字可以被定义为一种应用于（但不是唯一的）特定语言群体的书写系
    统；但具有与该语言群体不同的关键特征。它具有一种独特的语言特征，但不单如此。
    可以说巴列维文字为一种专门的书面文字系统；但许多巴列维文学本质上仍然是一种
    致力于表现白话文学的写作形式，也因此巴列维文学保留了许多白话文学作品的特征。

    url:https://zh.wikipedia.org/wiki/%E5%B7%B4%E5%88%97%E7%B6%AD%E6%96%87%E5%AD%97
    """
    return re.findall(r"[\u0840-\u085F]+", string)

def regex_find_Mandaic_char(string):
    """
    Regular extraction of Mandaic.
    曼达语

    wiki 参考：

        曼达语是阿拉姆语东南部的一种变体，由曼达人社区使用，传统上位于伊拉克南部
        和伊朗西南部，用于他们的宗教书籍。古典曼达伊语仍然被曼达教牧师用于礼仪仪式。
        古典曼达语的现代后裔，被称为新曼达语或现代曼达语，由阿瓦士周围的一小部
        分曼达人使用：XXXVI-XXXVIII，1-101和伊朗南部胡齐斯坦省的霍拉姆沙赫尔。

        古典曼达语的礼仪使用在伊朗（特别是该国南部），巴格达，伊拉克和侨民
        （特别是在美国，瑞典，澳大利亚和德国）被发现。它是一种东方阿拉姆语，
        以其大量使用元音字母（mater lectionis with aleph，他只在最后位置，
        'ayin，waw，yud））而闻名，所谓的plene拼写（曼达语字母）
        以及伊朗语和阿卡德语的数量语言对其词汇的影响，特别是在宗教
        和神秘术语领域。曼达语受到犹太巴勒斯坦阿拉姆语、撒玛利亚语亚拉姆语、
        希伯来语、希腊语、拉丁语的影响，此外还有阿卡德语和帕提亚语。

    url: https://en.wikipedia.org/wiki/Mandaic_language
    """
    return re.findall(r"[\u0840-\u085F]+", string)

def regex_find_Samaritan_char(string):
    """
    Regular extraction of Samaritan.
    塞玛利亚语

    wiki 参考：
        撒马利亚字母（英文：Samaritan script）由撒马利亚人用于宗教写作，
        撒马利亚五经就是以撒马利亚希伯来语写成的。该字母还被用于批注释，
        还有与撒马利亚阿拉姆语、偶尔也有阿拉伯语相关的翻译。

        撒马利亚字母是腓尼基字母变种古希伯来字母的直接分支。据推测，
        希伯来圣经的大部分内容最初都是用这种字母书写的，不过此说法
        并未在学界完全达成共识。古以色列人（包括犹太人和撒马利亚人）
        使用的原始西奈字母被认为是这种字母的派生源。

        犹太人所使用的广为人知的“方块字”希伯来字母，是一种阿拉米字母的风格化版本，
        被称作Ashurit（希伯来文：כתב אשורי）。按照圣经直译主义的说法，
        在《出埃及记》第32章第16节参中，这些字母是在西乃之地，
        上帝亲手写下的。在历史上，它在8世纪开始与腓尼基字母/古希伯来文字母产生差异。
        波斯帝国覆灭后，在最终确定阿拉米字母的形式之前，犹太教同时使用上述两种字母。
        在之后的一小段时间内，古希伯来字母（古撒马利亚字母）只被用来写四字神名，
        不久此习俗也被废除。

        此字母同样存在草写体。

        1631年，让·莫林出版了一份《撒马利亚五经》的手稿，这让撒马利亚字母开始为西方知晓。
        [2]1616年，旅行家彼得罗·德拉·瓦勒在大马士革买到了一份抄本。
        这份抄本现在被称为“密函B（Codex B）”。收藏于法国国家图书馆。[3]

    url:https://zh.wikipedia.org/wiki/%E6%92%92%E9%A9%AC%E5%88%A9%E4%BA%9A%E5%AD%97%E6%AF%8D
    """
    return re.findall(r"[\u0840-\u085F]+", string)

def regex_find_Devanagari_char(string):
    """
    Regular extraction of Devanagari.
    天成文书（梵文 、 印地语 、 梵語 、 尼泊尔语 ）

    wiki 参考：
        天城文（देवनागरी devanāgarī）又称天城体。是印度和尼泊尔的一种文字，
        用来书写印地语、梵语、尼泊尔语等语言。天城文最早出现在13世纪初，
        是城文变体之一，天城文是对城文的改良而成，改良后的城文为突出其神圣多
        加了个梵文“天”字（देव deva）成为天城文[1]。城文来自笈多文，笈多文
        犹如印度的其他文字一样，源自于前3世纪的婆罗米文。现在亚洲不少民族
        使用的字母与天城文的关系密切，而从帕拉瓦文派生的文字则在缅甸、
        泰国、柬埔寨、老挝等地使用。[2]

    url:https://zh.wikipedia.org/wiki/%E5%A4%A9%E5%9F%8E%E6%96%87
    """
    return re.findall(r"[\u0900-\u097F]+", string)

def regex_find_Bengali_char(string):
    """
    Regular extraction of Bengali.
    孟加拉语
    
    wiki 参考：

        孟加拉语（bāṅlā / বাংলা 或者 bāṅālī / বাঙালী）属于印欧语系印度-
        伊朗语族的印度-雅利安语支，是孟加拉国和印度西孟加拉邦和特里普拉
        邦的官方语言，使用人口约2亿2千万人，是印度-伊朗语族在印地语之后
        第二大语言。孟加拉语使用主要分布于孟加拉国和印度西孟加拉邦等。
        孟加拉语是1913年诺贝尔文学奖获得者英属印度的罗宾德拉纳特·泰戈尔的母语。

    url:https://zh.wikipedia.org/wiki/%E5%AD%9F%E5%8A%A0%E6%8B%89%E8%AF%AD
    """
    return re.findall(r"[\u0980-\u09FF]+", string)

def regex_find_Gurmukhi_char(string):
    """
    Regular extraction of Gurmukhi.
    锡克教语/旁遮普语/印度旁遮普语
    
    wiki 参考：
        Gurmukhī（旁遮普语：ਗੁਰਮੁਖੀ，旁遮普语发音：  [ˈɡʊɾᵊmʊkʰiː]，Shahmukhi：گُرمُکی）
        是一种从Laṇḍā 脚本发展而来的abugida，由第二位锡克教宗师4–1552ڬ（1502）标准化和使用
        。通常被认为是锡克文字，Gurmukhi 在印度旁遮普邦被用作旁遮普语的官方文字。
        锡克教的主要经文Guru Granth Sahib是用 Gurmukhī 写的，除了波斯语和印度-雅利安语的
        各个阶段之外，还使用各种方言和语言，通常归入通用标题Sant Bhasha 或圣语语言。
        现代 Gurmukhī 有 35 个原始字母，因此它的常用替代术语paintī或“三十五”，
        加上六个额外的辅音，九个元音 变音符号，两个鼻音变音符号，一个将辅音和三个下标字
        符连成一体的变音符号。
    
    url:https://zh.wikipedia.org/wiki/%E5%8F%A4%E5%8D%8E%E5%BA%93%E8%AF%AD
    """
    return re.findall(r"[\u0A00-\u0A7F]+", string)

def regex_find_Gujarati_char(string):
    """
    Regular extraction of Gujarati.
    古吉拉特语/印度古吉拉特语

    百度百科 参考:
        古吉拉特语（古吉拉特文：ગુજરાતી，拉丁化：Gujarātī）属于印欧语系印度语族，
        为印度22种官方语言与14种地区性语言之一，同时也是巴基斯坦少数民族语言。
        全球有大约4600万人讲这种语言，为世界上第23大语言。从使用的人群主要分布来看，
        印度4550万，乌干达15万，巴基斯坦10万，肯尼亚5万。古吉拉特语为印度古吉拉特邦、
        联邦属地达德拉-纳加尔哈维利和达曼-第乌的主要语言，同时也是孟买古吉拉特人社区
        的语言，在北美和英国有众多讲古吉拉特语的居民。古吉拉特语也是印度国父圣雄甘地、
        巴基斯坦国父穆罕默德·阿里·真纳和沙达·瓦拉汗·佩帖尔（被誉为铁人的印度首位内政大臣）
        的第一语言。
        """
    return re.findall(r"[\u0A80-\u0AFF]+", string)


def regex_find_Telugu_char(string):
    """
    Regular extraction of Telugu.
    泰卢固语/印度泰卢固语
        
    百度百科 参考:
        泰卢固语(తెలుగు)是印度安得拉邦(Andhara Pradesh)和泰兰戛纳(Telangana)
        泰卢固人的语言，印度宪法承认的语言之一。属达罗毗荼语系中部语族。使用人口超过8,000万，
        居同语系各语言之首。在东南亚、美国，印度洋和南太平洋中的岛屿，也有少数人使用。
        泰卢固语在公元前300～前100年间已经形成了自己的文学语言，并采取了南婆罗米字母。
        现代泰卢固文即由此发展而来。
    url:https://baike.baidu.com/item/%E6%B3%B0%E5%8D%A2%E5%9B%BA%E8%AF%AD
    """
    return re.findall(r"[\u0C00-\u0C7F]+", string)


def regex_find_Kannada_char(string):
    """
    Regular extraction of Kannada.
    卡纳达语/卡纳达语是印度卡纳塔克邦的官方语言

    """
    return re.findall(r"[\u0C80-\u0CFF]+", string)

def regex_find_Malayalam_char(string):
    """
    Regular extraction of Malayalam.
    马拉雅拉姆语/德拉维族语/印度拉姆语
    """
    return re.findall(r"[\u0D00-\u0D7F]+", string)

def regex_find_Sinhala_char(string):
    """
    Regular extraction of Sinhala.
    僧伽罗语/斯里兰卡语
    """
    return re.findall(r"[\u0D80-\u0DFF]+", string)

def regex_find_Thai_char(string):
    """
    Regular extraction of Thai.
    泰语
    """
    return re.findall(r"[\u0E00-\u0E7F]+", string)

def regex_find_Lao_char(string):
    """
    Regular extraction of Lao.
    老挝语
    """
    return re.findall(r"[\u0E80-\u0EFF]+", string)

def regex_find_Tibetan_char(string):
    """
    Regular extraction of Tibetan.
    藏语
    """
    return re.findall(r"[\u0F00-\u0FFF]+", string)

def regex_find_Myanmar_char(string):
    """
    Regular extraction of Myanmar.
    缅甸语
    """
    return re.findall(r"[\u1000-\u109F]+", string)

def regex_find_Georgian_char(string):
    """
    Regular extraction of Georgian.
    格鲁吉亚语
    """
    return re.findall(r"[\u10A0-\u10FF\u2D00-\u2D2F]+", string)

def regex_find_Hangul_char(string):
    """
    Regular extraction of Hangul.
    朝鲜语/韩语
    """
    return re.findall(r"[\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F]+", string)
    #return re.findall(r"[\u3130-\u318F]+",string)

def regex_find_Korea_char(string):
    """
    Regular extraction of Korea.
    朝鲜语/韩语
    """
    return regex_find_Hangul_char(string)

def regex_find_Yijing_Hexagrams_Symbols_char(string):
    """
    Regular extraction of Yijing Hexagrams Symbols.
    占卜卦
    """
    return re.findall(r"[\u4DC0-\u4DFF]+", string)


case = """

 en: Regular expression is a powerful tool for manipulating text. 
 zh: 汉语是世界上最优美的语言，正则表达式是一个很有用的工具 
 jp: 正規表現は非常に役に立つツールテキストを操作することです。 
 jp-char: あアいイうウえエおオ 
 kr:정규 표현식은 매우 유용한 도구 텍스트를 조작하는 것입니다. 
 """ 
print(regex_find_Hangul_char(case))
print(regex_find_Korea_char(case))
print(regex_find_Japanese_char(case))    

def regex_find_Coptic_char(string):
    """
    Regular extraction of Coptic.
    科普特语
    """
    return re.findall(r"[\u2C80-\u2CFF]+", string)

def regex_find_Ethiopic_char(string):
    """
    Regular extraction of Ethiopic.
    埃塞俄比亚语
    """
    return re.findall(r"[\u1200-\u137F]+", string)

def regex_find_Cherokee_char(string):
    """
    Regular extraction of Cherokee.
    切罗基语
    """
    return re.findall(r"[\u13A0-\u13FF]+", string)

def regex_find_Canadian_Aboriginal_Syllabics_char(string):
    """
    Regular extraction of Canadian Aboriginal Syllabics.
    加拿大土著语音节文字
    """
    return re.findall(r"[\u1400-\u167F]+", string)

def regex_find_Ogham_char(string):
    """
    Regular extraction of Ogham.
    欧甘文/欧洲语言/欧洲语系/欧洲语族
    """
    return re.findall(r"[\u1680-\u169F]+", string)

def regex_find_Runic_char(string):
    """
    Regular extraction of Runic.
    古代北欧文/盧恩字母/北欧文

    如尼文是一套字母表，在開始它屬於大約1500年前的北歐和日爾曼人。
    然而，這一“字母表”中的“字母”被認為包含著可以進行占卜的神秘因素。
    事實上，“如尼”（Rune）—詞意思是“神秘的”或“隱蔽的”。它來自於
    德語Raunen，其含義是“密談”。最早的並且實際上最聞名的如尼字母
    是老弗薩克（之所以叫弗薩克（futhark），是因為它代表起始的六
    個如尼字母Feoh、Ur、Thorn、Ansur、Rad和Ken）
    """
    return re.findall(r"[\u16A0-\u16FF]+", string)

def regex_find_Tagalog_char(string):
    """
    Regular extraction of Tagalog.
    塔加拉语/菲律賓语
    """
    return re.findall(r"[\u1700-\u171F]+", string)

def regex_find_Hanunoo_char(string):
    """
    Regular extraction of Hanunoo.
    哈努诺文/菲律賓语
    
    """
    return re.findall(r"[\u1720-\u173F]+", string)

def regex_find_Buhid_char(string):
    """
    Regular extraction of Buhid.
    布迪语/布希德语
    """
    return re.findall(r"[\u1740-\u175F]+", string)

def regex_find_Tagbanwa_char(string):
    """
    Regular extraction of Tagbanwa.
    塔格巴努亚语/塔格巴努语
    """
    return re.findall(r"[\u1760-\u177F]+", string)
   
def regex_find_Khmer_char(string):
    """
    Regular extraction of Khmer.
    高棉语/柬埔寨语
    """
    return re.findall(r"[\u1780-\u17FF]+", string)

def regex_find_Kmer_Symbols_char(string):
    """
    Regular extraction of Khmer Symbols.
    高棉语记号
    """
    return re.findall(r"[\u19E0-\u19FF]+", string)

def regex_find_Mongolian_char(string):
    """
    Regular extraction of Mongolian.
    蒙古语
    """
    return re.findall(r"[\u1800-\u18AF]+", string)

def regex_find_Cham_char(string):
    """
    Regular extraction of Cham.
    占文

    参考资料 ：《Cham script》
    作者 ： Frederic P. Miller，Agnes F. Vandome，John McBrewster
    占文是一种用于书写占文的abugida，占文是越南和柬埔寨约23万
    名占族人使用的一种奥罗尼西亚语言。它和英语一样，都是从左到
    右横向书写。占文是印度婆罗米文的后裔，婆罗米文本身就是阿拉
    米文的后裔。占文是最早从南印度婆罗米文发展而来的文字之一，
    称为Vatteluttu，大约在公元200年左右。它作为印度教和佛教
    扩张的一部分传入东南亚。占婆文明的印度教石庙中既有梵文，也
    有查谟文石刻。越南最早的碑文是在Mỹ Sơn寺庙群中发现的。最
    早的碑文可追溯到公元400年左右，是用错误的梵文书写的。此后，
    铭文在梵文和当时的占族语言之间交替出现。
    """
    return re.findall(r"[\u18B0-\u18FF]+", string)

def regex_find_Limbu_char(string):
    """
    Regular extraction of Limbu.
    林布语/尼泊尔语
    """
    return re.findall(r"[\u1900-\u194F]+", string)

def regex_find_Tai_Le_char(string):
    """
    Regular extraction of Tai Le.
    德宏泰语/中国民族语
    """
    return re.findall(r"[\u1950-\u197F]+", string)

def regex_find_New_Tai_Lue_char(string):
    """
    Regular extraction of New Tai Lue.
    新傣仂文/中国民族语
    """
    return re.findall(r"[\u1980-\u19DF]+", string)

def regex_find_Buginese_char(string):
    """
    Regular extraction of Buginese.
    布吉语
        布吉语是东南亚的一种语言，使用者分布于马来半岛、沙巴、加里曼丹、
        廖内省、苏门答腊，但主要用于印尼的南苏拉威西省，大约有500万人。
        布吉语使用的是婆罗米家族的隆塔拉字母,在荷兰殖民时期，它在很大程
        度上被拉丁字母所取代，尽管今天仍然在有限的范围内使用。隆塔拉这个
        术语来自马来语名称为palmyra palm，lontar，传统上用于手稿。在
        布吉语中意思是“四角字母”，引用了Bugis-Makasar对形成宇宙的四个
        元素的信念：火，水，空气和地球。
        隆塔拉字母是一个元音附标文字与23个基本辅音。与其他婆罗米系文字一
        样，隆塔拉字母的每个辅音带有一个固有的/ a /元音，在布吉语中发音
        为/ɔ/（类似的发音在爪哇文字中找到），它们通过变音符号变成以下元
        音之一; / i /，/ u /，/ e /，/ə/，或/ o /。然而，隆塔拉没有
        其它辅音结尾的变音符号。在布吉语言中使用的鼻/ŋ/，声门/ʔ/和
        gemination。因此，即使对于本地读者来说，也可能非常模糊。例如，
        ᨔᨑ可以被理解为萨拉 “悲伤”，“萨拉” “规则”或sarang“巢”。在布吉
        文人们利用这个有缺陷的语言作谜语。Basa to Bakke类似于双关语，
        其中具有不同含义但拼写相同的单词被操纵以产生具有隐藏信息的短语。
        隆塔拉字母是从左到右书写的，但也可以写成boustrophedically。
        这种方法主要应用于旧的布吉文期刊，其中每页保留一天的记录。如果一
        个抄写员用完了一天的书写空间，那么连续的行将被写在页面的旁边
        ，遵循Z字形图案，直到所有空间都被填满
        印度尼西亚民族。又称布吉斯人。主要分布在苏拉威西岛西南部、加里
        曼丹岛东南部和小巽他群岛部分地区。另有少数分布在马来西亚的雪兰
        莪州。属蒙古人种马来类型，系新马来人的后裔。使用布吉语，属南岛
        语系印度尼西亚语族。通用马来语和印度尼西亚语。14世纪即有本民族
        文字，以及用本民族文字创作的文学作品。信奉伊斯兰教，属逊尼派，
        但仍保留印度教和原始信仰残余。由若干村落组成一个地缘集团。有共
        同的神器，共同举行宗教活动，由称为比苏的祭司主持。主要从事农业，
        种植水稻，部分人从事畜牧业，饲养马、牛、羊；渔业和手工业亦很发
        达，他们还擅长航海，精于经商。
    """
    return re.findall(r"[\u1A00-\u1A1F]+", string)

def regex_find_Batak_char(string):
    """
    Regular extraction of Batak
    巴达克文字母/印度尼西亚
    """
    return re.findall(r"[\u1A20-\u1A5F]+", string)

# def regex_find_Sara_char(string):
#     """
#     Regular extraction of Sara
#     甘孜文字母/中华人民共和国
#     """
#     return re.findall(r"[\u0A80-\u0AFF]+", string)

def regex_find_Lanna_char(string):
    """
    Regular extraction of Lanna
    卢卡文字母/印度尼西亚
    """
    return re.findall(r"[\u1A80-\u1AEF]+", string)

def regex_find_Balinese_char(string):
    """
    Regular extraction of Balinese
    巴厘文字母/印度尼西亚
    """
    return re.findall(r"[\u1B00-\u1B7F]+", string)

def regex_find_Sundanese_char(string):
    """
    Regular extraction of Sundanese
    巽他文字母/印度尼西亚
    """
    return re.findall(r"[\u1B80-\u1BB0]+", string)

def regex_find_Pahawh_Hmong_char(string):
    """
    Regular extraction of Pahawh_Hmong
    巴哈姆文字母/印度尼西亚
    """
    return re.findall(r"[\u1BC0-\u1BFF]+", string)

def regex_find_Lepcha_char(string):
    """
    Regular extraction of Lepcha
    莱比文字母/雷布查语/中国
    """
    return re.findall(r"[\u1C00-\u1C4F]+", string)

















   

# test case

# print(regex_find_Russian_char('Ёжик под зелёной ёлкой.'))

# print(regex_find_Korean_char("中文混入 윤석열 대통령이 7일 국무회의에서 반도체 포토 마스크(레티클)를 들어 보인 데 대해 이종호 과학기술정보통신부 장관이 “실무를 알고 현장에 가보라는 메시지”라고 말했다. 이 장관은 이날 서울 용산구 대통령실에서 윤 대통령과 국무위원을 대상으로 ‘반도체 이해 및 전략적 가치’라는 주제로 특별 강연을 했다."))



# def Regular_extraction_of_Russian(string):
#     """
#     Regular extraction of Russian.
#     俄罗斯语
#     西里尔字母表
#     """
#     return re.findall(r"[А-Яа-я]+", string)


# def Regular_extraction_of_Japanese_character(string):
#     """
#     Regular extraction of Japanese character.
#     日语
#     """
#     return re.findall(r"[ぁ-ゞ]+", string)

# def Regular_extraction_of_Korean_character(string):
#     """
#     Regular extraction of Korean.
#     韩语
#     """
#     return re.findall(r"[가-힣]+", string)

# def Regular_extraction_of_Arabic_character(string):
#     """
#     Regular extraction of Arabic.
#     阿拉伯语
#     """
#     return re.findall(r"[أ-ي]+", string)

# def Regular_extraction_of_Thai(string):
#     """
#     Regular extraction of Thai.
#     泰语
#     """
#     return re.findall(r"[ก-๏]+", string)

# def Regular_extraction_of_German(string):
#     """
#     Regular extraction of German.
#     德语
#     """
#     return re.findall(r"[ä-ü]+", string)

# def Regular_extraction_of_Spanish(string):
#     """
#     Regular extraction of Spanish.
#     西班牙语
#     """
#     return re.findall(r"[á-ú]+", string)

# def Regular_extraction_of_Italian(string):
#     """
#     Regular extraction of Italian.
#     意大利语
#     """
#     return re.findall(r"[à-ù]+", string)

# def Regular_extraction_of_Portuguese(string):
#     """
#     Regular extraction of Portuguese.
#     葡萄牙语
#     """
#     return re.findall(r"[ã-õ]+", string)

# def Regular_extraction_of_Polish(string):
#     """
#     Regular extraction of Polish.
#     波兰语
#     """
#     return re.findall(r"[ą-ż]+", string)

# def Regular_extraction_of_Vietnamese(string):
#     """
#     Regular extraction of Vietnamese.
#     越南语
#     """
#     return re.findall(r"", string)

# def Regular_extraction_of_Czech(string):
#     """
#     Regular extraction of Czech.
#     捷克
#     """
#     return re.findall(r"[á-ž]+", string)

# def Regular_extraction_of_Swedish(string):
#     """
#     Regular extraction of Swedish.
#     瑞典语
#     """
#     return re.findall(r"[ä-å]+", string)

# def Regular_extraction_of_Danish(string):
#     """
#     Regular extraction of Danish.
#     丹麦
#     """
#     return re.findall(r"[æ-ø]+", string)

# def Regular_extraction_of_Norwegian(string):
#     """
#     Regular extraction of Norwegian.
#     挪威
#     """
#     return re.findall(r"[å-ø]+", string)

# def Regular_extraction_of_Finnish(string):
#     """
#     Regular extraction of Finnish.
#     芬兰语
#     """
#     return re.findall(r"[ä-ö]+", string)

# def Regular_extraction_of_Lithuanian(string):
#     """
#     Regular extraction of Lithuanian.
#     立陶宛语
#     """
#     return re.findall(r"[ą-ž]+", string)

# def Regular_extraction_of_Latvian(string):
#     """
#     Regular extraction of Latvian.
#     拉脱维亚语
#     """
#     return re.findall(r"[ā-ž]+", string)

# def Regular_extraction_of_Estonian(string):
#     """
#     Regular extraction of Estonian.
#     爱沙尼亚语
#     """
#     return re.findall(r"[ā-ž]+", string)

# def Regular_extraction_of_Hungarian(string):
#     """
#     Regular extraction of Hungarian.
#     匈牙利语
#     """
#     return re.findall(r"[á-ű]+", string)    


# def Regular_extraction_of_Turkish(string):
#     """
#     Regular extraction of Turkish.
#     土耳其语
#     """
#     return re.findall(r"[a-zA-ZğüıöşçİĞÜİÖŞÇ]+", string)

# def Regular_extraction_of_Greek(string):
#     """
#     Regular extraction of Greek.
#     希腊语
#     """
#     return re.findall(r"[Α-Ω]+", string)

# def Regular_extraction_of_Serbian(string):
#     """
#     Regular extraction of Serbian.
#     塞尔维亚语
#     """
#     return re.findall(r"[љ-џ]+", string)

# def Regular_extraction_of_Croatian(string):
#     """
#     Regular extraction of Croatian.
#     克罗地亚语
#     """
#     return re.findall(r"[č-ž]+", string)

# def Regular_extraction_of_Bulgarian(string):
#     """
#     Regular extraction of Bulgarian.
#     保加利亚语
#     """
#     return re.findall(r"[а-я]+", string)

# def Regular_extraction_of_Romanian(string):
#     """
#     Regular extraction of Romanian.
#     罗马尼亚语
#     """
#     return re.findall(r"[ă-ţ]+", string)

# def Regular_extraction_of_Ukrainian(string):
#     """
#     Regular extraction of Ukrainian.
#     乌克兰语
#     """
#     return re.findall(r"[а-щ]+", string)

# def Regular_extraction_of_Slovak(string):
#     """
#     Regular extraction of Slovak.
#     斯洛伐克语
#     """
#     return re.findall(r"[ä-ž]+", string)

# def Regular_extraction_of_Slovenian(string):
#     """
#     Regular extraction of Slovenian.
#     斯洛文尼亚语
#     """
#     return re.findall(r"[a-ž]+", string)

# def Regular_extraction_of_Macedonian(string):
#     """
#     Regular extraction of Macedonian.
#     马其顿语
#     """
#     return re.findall(r"[а-ё]+", string)


# def Regular_extraction_of_Hebrew(string):
#     """
#     Regular extraction of Hebrew.
#     希伯来语
#     """
#     return re.findall(r"[א-ת]+", string)

# def Regular_extraction_of_Maltese(string):
#     """
#     Regular extraction of Maltese.
#     马耳他语
#     """
#     return re.findall(r"[a-z]+", string)

# def Regular_extraction_of_Irish(string):
#     """
#     Regular extraction of Irish.
#     爱尔兰语
#     """
#     return re.findall(r"[a-z]+", string)

# def Regular_extraction_of_Welsh(string):
#     """
#     Regular extraction of Welsh.
#     威尔士语
#     """
#     return re.findall(r"[a-z]+", string)

# # def Regular_extraction_of_Basque(string):
# #     """
# #     Regular extraction of Basque.
# #     巴斯克语
# #     """
# #     return re.findall(r"[a-z]+", string)

# def Regular_extraction_of_Breton(string):
#     """
#     Regular extraction of Breton.
#     白里诺语
#     """
#     return re.findall(r"[a-z]+", string)

# def Regular_extraction_of_Corsican(string):
#     """
#     Regular extraction of Corsican.
#     科西嘉语
#     """
#     return re.findall(r"[a-z]+", string)

# def Regular_extraction_of_Scottish(string):
#     """
#     Regular extraction of Scottish.
#     苏格兰语
#     """
#     return re.findall(r"[a-z]+", string)

# def Regular_extraction_of_Galician(string):
#     """
#     Regular extraction of Galician.
#     加利西亚语
#     """
#     return re.findall(r"[a-z]+", string)

# def Regular_extraction_of_Manx(string):
#     """
#     Regular extraction of Manx.
#     曼岛语
#     """
#     return re.findall(r"[a-z]+", string)
# def Regular_extraction_of_Catalan(string):
#     """
#     Regular extraction of Catalan.
#     加泰罗尼亚语
#     """
#     return re.findall(r"[a-z]+", string)

# print(Regular_extraction_of_Latvian("latviešu valoda"),"拉脱维亚语")
# print(Regular_extraction_of_chinese("中文 你好世界"),"中文")
# print(Regular_extraction_of_Japanese("日本語 こんにちは世界"),"日语")
# print(Regular_extraction_of_French("français"),"法语")
# print(Regular_extraction_of_Korean("한국어 인사드세요"),"韩语")
# print(Regular_extraction_of_Arabic("العربية أهلا بالعالم"),"阿拉伯语")
# print(Regular_extraction_of_Hebrew("עִברִית שלום עולם"),"希伯来语")
# print(Regular_extraction_of_Russian("русский язык"),"俄语")
# print(Regular_extraction_of_Turkish("Türkçe русский язык"),"土耳其语")

#print(Regular_extraction_of_Swedish("Språkfamilj: Indoeuropeiska språk"),"瑞典语")

# print(Regular_extraction_of_Bulgarian("čeština,български"),"捷克语")
# print(Regular_extraction_of_Croatian("hrvatski krōˈāSHən"),"克罗地亚语")
# print(Regular_extraction_of_Basque("Euskara"),"巴斯克语")
# print(Regular_extraction_of_Breton("chinese  brezhoneg"),"白里诺语")
# print(Regular_extraction_of_Catalan("English català"),"加泰罗尼亚语")





# print("Regular extraction of symbol:", Regular_extraction_of_symbol("!@#$%^&*()_+-=[]{}|;':,./<>?`~"))
# print(Regular_extraction_of_chinese("你好，世界！1234567890 hello word"))
# print(Regular_extraction_of_chinese_and_symbol("你好，世界！1234567890 hello word"))
# print(Regular_extraction_of_chinese_and_number_and_symbol("你好，世界！1234567890 hello word"))

