from Preprocessing_application_code import extract_features
import numpy as np
import pickle
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import load_model
import tensorflow as tf
import os

# 현재 파일(run_preprocessing.py)의 경로
current_dir = os.path.dirname(__file__)

# model 폴더 안의 Recall_0.77.keras 경로 조합
model_path = os.path.join(current_dir, "model", "White_list_model.keras")
scaler_path = os.path.join(current_dir, "model", "scaler.pkl")

# 모델 불러오기
model = load_model(model_path)

# 스케일링 파일 불러오기
with open(scaler_path,'rb') as f:
    scaler = pickle.load(f)

# @tf.function을 사용하여 예측 최적화
@tf.function(reduce_retracing=True)
def predict_with_model(model, input_data):
    return model(input_data)

# 입력값 받기
url = input("확인할 URL을 입력하세요 : ")

# 특성 추출
feature = extract_features(url)
input_df = pd.DataFrame([list(feature.values())], columns=feature.keys())

# 스케일링
input_scaled = scaler.transform(input_df)

# 예측
prediction = predict_with_model(model, input_scaled)

# 결과 출력
best_threshold = 0.5  # 예시로 임계값을 설정, 실제 값으로 교체해야 합니다.
if prediction[0][0] > best_threshold:
    print(f"입력값 : {url} \n악성 URL로 의심됩니다. (score {round(float(prediction[0][0]), 4)})")
else:
    print(f"입력값 : {url} \n정상 URL로 의심됩니다. (score {round(float(prediction[0][0]), 4)})")
