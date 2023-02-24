from jieba import cut 
from nltk import download, word_tokenize
from os.path import exists,expanduser
if exists(expanduser('~/nltk_data/tokenizers/punkt/english.pickle')):
    print("nltk tokenizer is already downloaded")
else:
    print("need to download nltk tokenizer \n downloading nltk tokenizer...")
    download('punkt')

def tokenize_for_chinese(text):
    '''
    use jieba to tokenize text
    '''
    return list(cut(text))

def tokenize_for_english(text):
    '''
    use nltk to tokenize text
    '''
    return word_tokenize(text)


print(tokenize_for_chinese("我是中国人"))
print(tokenize_for_english("hello world"))
