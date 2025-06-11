import re
from urllib.parse import urlparse, parse_qs
import tldextract
import zlib
import re
from urllib.parse import urlparse
from collections import Counter
import math



def check_similar_brand(url):
    # 자주 사용되는 브랜드/도메인 목록
    common_brands = {
        'google', 'facebook', 'amazon', 'microsoft', 'apple', 
        'netflix', 'paypal', 'twitter', 'instagram', 'linkedin',
        'youtube', 'yahoo', 'gmail', 'whatsapp', 'tiktok',
        'geocities', 'angelfire', 'newadvent', 'wikipedia',
    }
    
    # 2. 유사 브랜드 확인
    try:
        # URL 파싱
        parsed = urlparse(url if '//' in url else '//' + url)
        domain = parsed.netloc.lower() if parsed.netloc else url.lower()
        
        for brand in common_brands:
            if brand not in domain:
                similar = False
                # 비슷한 철자 패턴 확인
                patterns = [
                    brand.replace('o', '0'),
                    brand.replace('i', '1'),
                    brand.replace('l', '1'),
                    brand.replace('e', '3'),
                    brand.replace('a', '4'),
                    brand.replace('s', '5'),
                    brand + '-',
                    brand + '_',
                    brand[:-1],  # 마지막 문자 제거
                    ''.join(c + c for c in brand),  # 문자 중복
                ]
                
                for pattern in patterns:
                    if pattern in domain:
                        similar = True
                        break
                
                if similar:
                    return True  # 유사 브랜드가 발견되면 True 반환
        
    except Exception as e:
        return False  # 예외 발생 시 False 반환
    
    return False  # 유사 브랜드가 없으면 False 반환



# url 압축 비율 계산 함수
def compression_ratio(url: str) -> float:
    if not url:
        return 0.0
    original_length = len(url.encode('utf-8'))
    compressed_data = zlib.compress(url.encode('utf-8'))
    compressed_length = len(compressed_data)
    return compressed_length / original_length


def extract_features(url):
    parsed_url = urlparse(url)
    suspicious_keywords = [
        'login', 'verify', 'account', 'update', 'secure', 'banking', 
        'paypal', 'confirm', 'signin', 'auth', 'redirect', 'free', 
        'bonus', 'admin', 'support', 'server', 'password', 'click', 
        'urgent', 'immediate', 'alert', 'security', 'prompt'
    ]
    
    additional_keywords = [
        'verify', 'wallet', 'cryptocurrency', 'bitcoin', 'ethereum',
        'validation', 'authenticate', 'reset', 'recover', 'access',
        'limited', 'offer', 'prize', 'win', 'winner', 'payment',
        'bank', 'credit', 'debit', 'card', 'expire', 'suspension',
        'unusual', 'activity', 'verify', 'document', 'invoice'
    ]
    
    all_keywords = list(set(suspicious_keywords + additional_keywords))

    contains_keyword = 0
    keyword_count = 0
    for keyword in all_keywords:
        if re.search(r'\b' + keyword + r'\b', url, re.IGNORECASE):
            contains_keyword = 1
            keyword_count += 1
    
    url_length = len(url)
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    domain = extracted.domain
    subdomain = extracted.subdomain

    tld_length = len(tld) if tld else 0
    common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'info', 'biz']
    is_common_tld = 1 if tld in common_tlds else 0
    country_tlds = ['us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in', 'it', 'es']
    is_country_tld = 1 if tld in country_tlds else 0
    suspicious_tlds = ['xyz', 'top', 'club', 'online', 'site', 'icu', 'vip', 'work', 'rest', 'fit']
    is_suspicious_tld = 1 if tld in suspicious_tlds else 0
    url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc']
    full_domain = f"{domain}.{tld}" if tld else domain
    is_shortened = 1 if full_domain in url_shorteners else 0


    domain_length = len(domain) if domain else 0
    has_subdomain = 1 if subdomain else 0
    subdomain_length = len(subdomain) if subdomain else 0
    subdomain_count = len(subdomain.split('.')) if subdomain else 0 

    path = parsed_url.path
    path_length = len(path)
    path_depth = path.count('/') if path else 0

    query = parsed_url.query
    has_query = 1 if query else 0
    query_length = len(query) if query else 0
    query_params = parse_qs(query)
    query_param_count = len(query_params) if query_params else 0

    has_fragment = 1 if parsed_url.fragment else 0
    fragment_length = len(parsed_url.fragment) if parsed_url.fragment else 0
    
    # Character type ratios
    letter_count = sum(c.isalpha() for c in url)
    digit_count = sum(c.isdigit() for c in url)
    special_char_count = len(re.findall(r'[^a-zA-Z0-9]', url))
    
    letter_ratio = letter_count / url_length if url_length > 0 else 0
    digit_ratio = digit_count / url_length if url_length > 0 else 0
    special_char_ratio = special_char_count / url_length if url_length > 0 else 0
    
    # Character distribution and entropy
    if url:
        char_counts = Counter(url)
        total_chars = len(url)
        char_frequencies = {char: count/total_chars for char, count in char_counts.items()}
        entropy = -sum(freq * math.log2(freq) for freq in char_frequencies.values())
    else:
        entropy = 0





    if url_length <= 13:
        url_length_cat = 0  
    elif url_length <= 18:
        url_length_cat = 1 
    elif url_length <= 25:
        url_length_cat = 2 
    else:
        url_length_cat = 3 

    return {
        # "url_length": url_length,
        "url_length_cat": url_length_cat,
        "num_dots": url.count("."),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", url)),
        "url_keyword": contains_keyword,
        # "url_keyword_count": keyword_count,
        "num_underbar": url.count("_"),
        "extract_consecutive_numbers": int(bool(re.findall(r'(\d)\1+', url))),
        "number": int(bool(len(re.findall(r'(\d)(?!\1)(\d)(?!\2)(\d)', url)))),
        "upper": int(any(c.isupper() for c in url)),

        "is_common_tld": is_common_tld,
        "is country_tld": is_country_tld,
        "is_suspicious_tld": is_suspicious_tld,

        "domain_length": domain_length,
        "has_subdomain": has_subdomain,
        "subdomain_length": subdomain_length,
        "subdomain_count": subdomain_count,

        # "path_length": path_length,
        "path_depth": path_depth,
        "has_query": has_query,
        "query_length": query_length,
        "query_param_count": query_param_count,
        # "has_fragment": has_fragment,
        # "fragment_length": fragment_length,
        "url_shorteners": is_shortened,

        # 새로 추가된 특성
        "compression_ratio": compression_ratio(url),
        "check_similar_brand" : check_similar_brand(url),
 
        # Advanced text analysis
        "entropy": entropy,
        #"letter_ratio": letter_ratio,
        "digit_ratio": digit_ratio,
        "special_char_ratio": special_char_ratio

        
    }
