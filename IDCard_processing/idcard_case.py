import json
import pandas as pd
from os.path import expanduser

new_table = open(expanduser("~/mingyueguan_project/IDCard_processing/全国大全身份证前六位、区号、邮编-编码.csv")).readlines()
#new_table = new_table[['身份证前六位', '省份', '城市', '区/县', '简称', '电话区号', '邮政编码']]
result = {'身份证前六位':[], '省份':[], '城市':[], '区/县':[], '简称':[], '电话区号':[], '邮政编码':[]}
header = new_table[0].split(",")
for line in new_table[1:]:
    temp = line.split(",")[:7]
    id1to6 = str(temp[0])
    province = str(temp[1])
    city = str(temp[2])
    county = str(temp[3])
    sname = str(temp[4])
    tell_code = str(temp[5])
    No = str(temp[6])
    result['身份证前六位'].append(id1to6)
    result['省份'].append(province)
    result['城市'].append(city)
    result['区/县'].append(county)
    result['简称'].append(sname)
    result['电话区号'].append(tell_code)
    result['邮政编码'].append(No)
#result_df = pd.DataFrame(result)
#result_df.to_csv("全国大全身份证前六位、区号、邮编-编码.csv",index=False)
result_json = json.dumps(result, ensure_ascii=False
                         , indent=4, sort_keys=True
                         #, separators=(',', ':')
                         #, encoding='utf-8'
                         #, errors='ignore'
                         , default=str
                         , skipkeys=True
                         , check_circular=True
                         , allow_nan=True
                         #, cls=None
                         #, indent_space=None
                         , separators=None)
with open(expanduser("~/mingyueguan_project/IDCard_processing/record.json"),"w") as f:
    json.dump(result_json,f)
    print("加载入文件完成...")

 
    

    
    
     