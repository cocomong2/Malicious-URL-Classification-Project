from app.PreP import preprocess_single_url
import joblib
import numpy as np
import os

# 현재 파일 기준 경로
current_dir = os.path.dirname(os.path.abspath(__file__))

# 절대 경로로 모델 로드
models_load = [
    joblib.load(os.path.join(current_dir, 'models', f'sampled_xgboost_model_{i+1}.joblib'))
    for i in range(4)
]



# 최적 임계값
best_threshold = 0.7211
# best_threshold = 0.7 # recall을 우선할 때의 임계값

def use_model(url : str):
    # 전처리 함수를 호출하여 피처를 가진 데이터 프레임 생성
    featured_df = preprocess_single_url(url)

    # 모델에 적용할 피처 추출
    features_cols = []
    except_cols = ['URL'] # 모델에 적용하지 않을 피처
    features_cols = (col for col in featured_df.columns if col not in except_cols)
    input_data = featured_df[features_cols]

    # 학습된 모델에 적용
    model_pred = round(float(np.mean([model.predict_proba(input_data)[:, 1] for model in models_load])), 4)

    return model_pred
