import numpy as np
import pandas as pd
import string
import re
from urllib.parse import urlparse, parse_qs
import tldextract
from collections import Counter
import math
import zlib
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler


### 전처리에 사용할 함수 정의


## 필요 데이터

suspicious_keywords = ["PayPal", "login", "signin", "bank", "account", "update", "free", "lucky", \
    "service", "bonus", "ebayisapi", "webscr", "verify", "secure", "banking", \
    "paypal", "confirm", "auth", "redirect", "admin", "support", "server", \
    "password", "click", "urgent", "immediate", "alert", "security", "prompt"]

# suspicious keywords 추가
additional_keywords = [
    'verify', 'wallet', 'cryptocurrency', 'bitcoin', 'ethereum',
    'validation', 'authenticate', 'reset', 'recover', 'access',
    'limited', 'offer', 'prize', 'win', 'winner', 'payment',
    'bank', 'credit', 'debit', 'card', 'expire', 'suspension',
    'unusual', 'activity', 'verify', 'document', 'invoice'
]
    
# suspicious keywords 전체 목록
all_keywords = list(set(suspicious_keywords + additional_keywords))
    
# 피싱에 자주 사용되는 브랜드 목록
popular_brands = [
    'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google',
    'facebook', 'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'amex', 'americanexpress', 'dropbox',
    'yahoo', 'outlook', 'office365', 'onedrive', 'icloud', 'gmail'
]

# 국가 도메인을 나타내는 2자리 영문 목록
ccTLDs = [
    'ac', 'ad', 'ae', 'af', 'ag', 'ai', 'al', 'am', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'aw', 'ax', 'az',
    'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bm', 'bn', 'bo', 'br', 'bs', 'bt', 'bv', 'bw', 'by', 'bz',
    'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr', 'cu', 'cv', 'cw', 'cx', 'cy', 'cz',
    'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ee', 'eg', 'eh', 'er', 'es', 'et', 'eu',
    'fi', 'fj', 'fk', 'fm', 'fo', 'fr',
    'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gp', 'gq', 'gr', 'gt', 'gu', 'gw', 'gy',
    'hk', 'hm', 'hn', 'hr', 'ht', 'hu',
    'id', 'ie', 'il', 'im', 'in', 'io', 'iq', 'ir', 'is', 'it',
    'je', 'jm', 'jo', 'jp',
    'ke', 'kg', 'kh', 'ki', 'km', 'kn', 'kp', 'kr', 'kw', 'ky', 'kz',
    'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 'ly',
    'ma', 'mc', 'md', 'me', 'mg', 'mh', 'mk', 'ml', 'mm', 'mn', 'mo', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'my', 'mz',
    'na', 'nc', 'ne', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz',
    'om',
    'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn', 'pr', 'pt', 'pw', 'py',
    'qa',
    're', 'ro', 'rs', 'ru', 'rw',
    'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si', 'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'ss', 'st', 'sv', 'sx', 'sy', 'sz',
    'tc', 'td', 'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tr', 'tt', 'tv', 'tw', 'tz',
    'ua', 'ug', 'uk', 'um', 'us', 'uy', 'uz',
    'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu',
    'wf', 'ws',
    'ye', 'yt',
    'za', 'zm', 'zw'
]

# 스케일링을 적용하는 피처들
nor_col = ['subdomain_count', 'digits_count', 'special_chars_count', 
 'path_depth', 'max_numeric_sequence', 'suspicious_keyword_count', 
 'repeated', 'num_underbar', 'query_length', 'query_param_count']

# 자주 사용되는 악성 국가 도메인
suspicious_tlds = ['ru', 'cn', 'br', 'np', 'tk', 'ml', 'ga', 'cf', 'ro', 'su']


## 필요 함수 정의

# 개수 카운트 하기
def count_letters(url):
    num_letters = sum(char.isalpha() for char in url)

    return num_letters

def count_digits(url):
    num_digits = sum(char.isdigit() for char in url)

    return num_digits

def count_special_chars(url):
    special_chars = set(string.punctuation)
    num_special_chars = sum(char in special_chars for char in url)

    return num_special_chars

# ip 주소 형식 사용 여부
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

# 파일 확장자 포함 여부
def file_ext(url):
    match = re.search(".php|.html|.htm|.hwp|.hwpx|.pptx|.docx|.iso|.js|.lnk|.vbs|.xls|.xml|.zip|.xlsx", url)
    if match:
        return 1
    else:
        return 0

# URL 길이를 범주형 값(0~3)으로 변환하는 함수
def categorize_url_length(length):
    if length <= 12:
        return 0
    elif length <= 16:
        return 1
    elif length <= 22:
        return 2
    else:
        return 3

# 피싱에 주로 사용되는 위험 단어들을 포함하는지 여부
def count_suspicious_keywords(text: str) -> int:
    return sum(len(re.findall(keyword, text, flags=re.IGNORECASE)) for keyword in suspicious_keywords)

# 반복된 숫자 여부
def repeated_num(url):
    repeat_num = len(re.findall(r'(\d)\1+', url)) # 같은 수 반복 찾기, 반복이 없으면 0
    if repeat_num > 0: # 반복이 나타나면 1을 리턴
        return 1
    else: # 반복이 없으면 0을 리턴
        return 0

# 반복된 숫자 갯수
def repeated(url):
    repeat_num = len(re.findall(r'(\d)\1+', url)) # 같은 수 반복 찾기, 반복이 없으면 0

    return repeat_num

# URL 주소에 쿼리를 가지고 있는지 여부
def has_query_f(url):
    parsed_url = urlparse(url)
    query = parsed_url.query
    has_query = 1 if query else 0

    return has_query

# URL 주소에 가지고 있는 쿼리의 길이
def query_length_f(url):
    parsed_url = urlparse(url)
    query = parsed_url.query
    query_length = len(query) if query else 0

    return query_length

# 쿼리에 가지고 있는 파라미터의 갯수
def query_params_f(url):
    parsed_url = urlparse(url)
    query = parsed_url.query
    query_params = parse_qs(query) # Count query parameters
    query_param_count = len(query_params) if query_params else 0

    return query_param_count

# 샤논 엔트로피
#   악성 URL의 경우, 난수 기반의 서브 도메인,
#   Base64 기반 인코딩, 복잡한 문자 조합 등을 사용하기에 엔트로피가 높게 나타남
def entropy_f(url):
    if url:
        char_counts = Counter(url)
        total_chars = len(url)
        char_frequencies = {char: count/total_chars for char, count in char_counts.items()} # 빈도 비율
        entropy = -sum(freq * math.log2(freq) for freq in char_frequencies.values()) # 샤논 엔트로피 공식
    else:
        entropy = 0
    
    return entropy

# 서브도메인을 가지고 있으며, 그것이 숫자를 포함하고 있는지 여부
def subdomain_f(url):
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    has_numeric_subdomain = 1 if subdomain and any(c.isdigit() for c in subdomain) else 0

    return has_numeric_subdomain

# URL에서 연속된 자음으로 구성된 길이의 비율을 계산
def consonant_ratio(url):
    url = url.lower()
    # 자음만으로 이루어진 5글자 이상 연속된 패턴 탐색 (의미 없는 문자열 판단 기준)
    consonant_groups = re.findall(r'[^aeiou\W\d_]{5,}', url)
    total_consonant_len = sum(len(group) for group in consonant_groups)
    
    return total_consonant_len / len(url) if len(url) > 0 else 0

# 포트 번호
def has_port_number(url):
    """
    URL에 포트 번호(:숫자)가 포함되어 있는지를 확인
    """
    # 정규표현식으로 ":숫자" 형태를 찾음 (예: :8080)
    match = re.search(r':\d{2,5}(?=/|$)', url)
    return int(bool(match))
    
# 반복되는 같은 패턴 갯수
def repeated_char_count(url):
    repeated = re.findall(r'(.)\1{2,}', url)  # 같은 문자 3번 이상 반복
    # '0'은 제외하고 나머지 문자 개수만 카운트
    filtered = [char for char in repeated if char != '0']
    return len(filtered)

# 3-gram 엔트로피를 샤논 엔트로피 방식으로 계산하고 정규화를 수행
def ngram_entropy_norm(text, n=3):
    if not text or len(text) < n:
        return 0.0
    
    ngrams = [text[i:i+n] for i in range(len(text) - n + 1)]
    total = len(ngrams)
    ngram_counts = Counter(ngrams)

    # 엔트로피 계산
    probs = [count / total for count in ngram_counts.values()]
    entropy = -sum(p * math.log2(p) for p in probs)

    # 정규화를 수행하고 리턴
    max_entropy = math.log2(len(ngram_counts)) if len(ngram_counts) > 1 else 1
    
    return entropy / max_entropy

# 문자열의 다양성을 계산
def unique_char_ratio(url: str) -> float:
    if not url:
        return 0.0
        
    return len(set(url)) / len(url)

# .cc 형식으로 끝나는 국가 도메인을 가진 URL을 확인하는 피처
def has_country_domain(url):
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        hostname = parsed.hostname
        if hostname:
            domain_parts = hostname.lower().split('.')
            if len(domain_parts) >= 2:
                last_part = domain_parts[-1]
                return 1 if last_part in ccTLDs else 0
    except:
        pass
    return 0

# 악성 국가 도메인을 포함하는지 여부
def has_suspicious_tlds(url):
    try:
        # 스킴이 없으면 http:// 붙이기
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.lower()
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            tld = domain_parts[-1]
            return 1 if tld in suspicious_tlds else 0
    except Exception as e:
        pass
    return 0

# 흔하게 사용되는 tld 포함 여부
def common_tld(url):
    common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'info', 'biz']
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    is_common_tld = 1 if tld in common_tlds else 0

    return is_common_tld

# 악성 url에 자주 사용되는 tld 포함 여부
def haz_tld(url):
    haz_tlds = ['xyz', 'top', 'club', 'online', 'site', 'icu', 'vip', 'work', 'rest', 'fit']
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    is_haz_tld = 1 if tld in haz_tlds else 0

    return is_haz_tld

# 축약형 url 포함 여부
def has_shortener(url):
    try:
        url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc']
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        return 1 if domain in url_shorteners else 0
    except:
        return 0

## 피처 정규화

# 데이터프레임에서 숫자 형식(int, float)의 피처를 정규화
# 이진 분류, 카테고리형인 컬럼은 제외
def normalize_features(df):
    exclude_cols = ['label', 'use_of_ip', 'file_extension', \
                    'url_length_cat', 'has_suspicious_keyword', 'repeated_num', \
                    'numer', 'upper', 'has_query', 'has_numeric_subdomain']
    
    # 정규화를 적용할 컬럼 탐색
    num_cols = df.select_dtypes(include=['int64', 'float64']).columns
    num_cols = [col for col in num_cols if col not in exclude_cols]
    
    # StandardScaler를 사용하여 지정된 피처를 정규화
    scaler = StandardScaler()
    df[num_cols] = scaler.fit_transform(df[num_cols])
    
    return df




## 전처리 함수 적용

# 입력 URL을 처리하는 함수
# String 형식의 URL을 입력 받아서 전처리 후 DataFrame 형식으로 Return
# 총 N개 컬럼(피처)을 생성
def preprocess_single_url(url):
    # 초기 데이터프레임 생성
    df = pd.DataFrame({'URL': [str(url)]})
    
    # 전처리를 통해 컬럼(피처) 추가
    df['subdomain_count'] = df['URL'].str.split('.').apply(lambda x: len(x) - 2) # 서브 도메인 갯수
    df['letters_count'] = df['URL'].apply(count_letters) # 문자 갯수
    df['digits_count'] = df['URL'].apply(count_digits) # 숫자 갯수
    df['special_chars_count'] = df['URL'].apply(count_special_chars) # 특수 문자 갯수
    df['use_of_ip'] = df['URL'].apply(lambda i: having_ip_address(i)) # ip 주소 형식 사용 여부
    df['path_depth'] = df['URL'].str.count('/') # / 갯수를 활용한 URL 깊이
    df['max_numeric_sequence'] = df['URL'].apply(lambda x: max([len(seq) for seq in re.findall(r'\d+', x)] or [0])) # 최대 연속된 숫자 길이
    df['file_extension'] = df['URL'].apply(lambda i: file_ext(i)) # 확장자 포함 여부
    df['special_char_count'] = df['URL'].apply(lambda x: sum(1 for c in x if c in '-_/')) # 특수 문자('-', '_', '/') 개수
    df['url_length_cat'] = df['letters_count'].apply(categorize_url_length) # url 길이에 따른 범주화
    df['suspicious_keyword_count'] = df['URL'].apply(count_suspicious_keywords) # 위험 단어 보유 갯수
    df['has_suspicious_keyword'] = (df['suspicious_keyword_count'] > 0).astype(int) # 위험 단어 보유 여부
    df['repeated'] = df['URL'].apply(repeated)
    df['repeated_num'] = df['URL'].apply(repeated_num)
    df['num_underbar'] = df['URL'].apply(lambda url : url.count("_"))
    df['numer'] = df['URL'].apply(lambda url : int(bool(len(re.findall(r'(\d)(?!\1)(\d)(?!\2)(\d)', url)))))
    df["upper"] = df['URL'].apply(lambda url : int(any(c.isupper() for c in url)))
    df['has_query'] = df['URL'].apply(has_query_f)
    df['query_length'] = df['URL'].apply(query_length_f)
    df['query_param_count'] = df['URL'].apply(query_params_f)
    df['entropy'] = df['URL'].apply(entropy_f)
    df['has_numeric_subdomain'] = df['URL'].apply(subdomain_f)

    # 생성된 피처에 정규화 수행
    df = normalize_features(df)
    
    df['has_port_number'] = df['URL'].apply(has_port_number)
    df['consonant_ratio'] = df['URL'].apply(consonant_ratio)
    df['repeated_char_count'] = df['URL'].apply(repeated_char_count)
    df['ngram_entropy_norm'] = df['URL'].apply(ngram_entropy_norm)
    df['unique_char_ratio'] = df['URL'].apply(unique_char_ratio)
    df['has_country_domain'] = df['URL'].apply(has_country_domain)
    
    scaler = MinMaxScaler()
    for col in nor_col:
        new_col_name = f'{col}_scaled'
        df[new_col_name] = scaler.fit_transform(df[[col]])
        df.drop(col, axis = 1, inplace = True)

    df['has_suspicious_tlds'] = df['URL'].apply(has_suspicious_tlds)
    df['has_common_tlds'] = df['URL'].apply(common_tld)
    df['has_hazardous_tlds'] = df['URL'].apply(haz_tld)
    df['has_shorteners'] = df['URL'].apply(has_shortener)

    df.drop(columns = ['letters_count', 'special_char_count'], axis = 1, inplace = True)


    return df