from app.junPreP import extract_features
import numpy as np
import pickle
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import load_model
import tensorflow as tf
import os

# 모델 및 스케일러 경로 (FastAPI 기준으로 맞춰서 절대 경로 또는 경로 설정)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "Recall_0.77.keras")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

# 모델 및 스케일러 로드 (1회만 수행)
model = load_model(MODEL_PATH)
with open(SCALER_PATH, 'rb') as f:
    scaler = pickle.load(f)

# @tf.function으로 추론 최적화
@tf.function(reduce_retracing=True)
def predict_with_model(model, input_data):
    return model(input_data)

# Threshold (적절히 조정 가능)
BEST_THRESHOLD = 0.4034

# 📦 예측 함수 정의 (FastAPI에서 import해서 사용)
def predict_url_maliciousness(url: str) -> dict:
    # 특성 추출
    features = extract_features(url)
    input_df = pd.DataFrame([list(features.values())], columns=features.keys())

    # 스케일링
    input_scaled = scaler.transform(input_df)

    # 예측
    prediction = predict_with_model(model, input_scaled)
    malicious_prob = float(prediction[0][0])

    # 임계값 기반 판단
    is_malicious = bool(malicious_prob > BEST_THRESHOLD)

    # Ensure all values are Python native types (not numpy types)
    return {
        "url": str(url),
        "malicious_probability": float(malicious_prob),
        "is_malicious": bool(is_malicious),
        "threshold": float(BEST_THRESHOLD)
    }


