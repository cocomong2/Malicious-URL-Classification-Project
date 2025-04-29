### url 입력 값을 넣어서 사용하는 방법 참고용 파일


from model_load import use_model

# 잡코리아 모집 공고
test_url = "https://www.jobkorea.co.kr/Recruit/GI_Read/46714754?Oem_Code=C1&productType=FirstVVIP&logpath=0&sc=511"

result = use_model(test_url)
print(result)