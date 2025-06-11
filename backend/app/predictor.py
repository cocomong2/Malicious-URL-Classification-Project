import joblib
import os
from app.PreP import preprocess_single_url
import numpy as np

# model directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

'''
# 임의의 url을 입력하고 함수 적용하여 전처리
url_test = 'https://www.msn.com/ko-kr/news/other/%EC%84%9C%EB%B2%84%EC%97%90-%EC%82%AC%EC%A7%84-%EC%95%88-%EC%98%AC%EB%A6%AC%EA%B3%A0%EB%8F%84-%EC%A7%80%EB%B8%8C%EB%A6%AC%ED%92%8D%EC%9C%BC%EB%A1%9C-%EC%82%AC%EC%83%9D%ED%99%9C-%EC%B9%A8%ED%95%B4-%EB%A7%89%EB%8A%94-ai-%EA%B0%9C%EB%B0%9C/ar-AA1CyK6x?ocid=msedgntp&pc=U531&cvid=fdbbff03231b4babb8bf42b0036d8141&ei=9' # 테스트할 URL 입력
url_pre = preprocess_single_url(url_test) 
'''

# 훈련에 사용할 features
features_cols = ['subdomain_count', 'letters_count', \
       'digits_count', 'special_chars_count', 'use_of_ip', 'path_depth', \
       'max_numeric_sequence', 'file_extension', 'special_char_count', \
       'url_length_cat', 'suspicious_keyword_count', 'has_suspicious_keyword']

'''
# 적용할 데이터
input_data = url_pre[features_cols]
'''

## threshold 설정
BEST_THRESHOLD = 0.6563

## 모델 불러오기

# 단일 모델 불러오기
# model_load = joblib.load('xgboost_model_fold1.pkl')

# 여러 모델 불러오기
models_load = [joblib.load(os.path.join(MODEL_DIR, f'xgboost_model_fold{i+1}.pkl')) for i in range(4)]

## threshold 설정
BEST_THRESHOLD = 0.6563

def predict_url(url: str) -> dict:
    try:
        preprocessed = preprocess_single_url(url)
        input_data = preprocessed[features_cols]
        
        # ✅ 전처리된 데이터 확인
        print("Preprocessed input:", input_data)

        # 평균 확률 계산
        probs = [float(model.predict_proba(input_data)[0, 1]) for model in models_load]
        mean_pred = float(np.mean(probs))

         # 모델 예측 결과 확인
        print("Model prediction result:", mean_pred)

        # 진단 결과 판단
        is_malicious = bool(mean_pred > BEST_THRESHOLD)

       

        # 예: malicious_probability가 np.float32 타입일 경우
        return {
            "url": url,
            "malicious_probability": mean_pred,  # ⬅️ numpy -> float
            "is_malicious": bool(is_malicious),         # ⬅️ numpy -> bool
            "threshold": float(BEST_THRESHOLD)          # ⬅️ numpy -> float
        }


    except Exception as e:
        return {"error": str(e)}

