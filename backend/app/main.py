from fastapi import FastAPI
from pydantic import BaseModel
from app.model_load import use_model  # predictor.py에서 함수 import
from app.exe import predict_url_maliciousness
from app.utils import convert_numpy_to_python_types
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# FastAPI 인스턴스에 CORS 미들웨어 추가
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 또는 ["http://localhost:3000"] (프론트 URL)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 요청 데이터 구조 정의
class UrlRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"message": "URL 악성 판별기 FastAPI 서버 정상 작동 중!"}

@app.post("/predict")
def predict(request: UrlRequest):
     url = request.url

     result_model1 = convert_numpy_to_python_types(use_model(url))
     result_model2 = convert_numpy_to_python_types(predict_url_maliciousness(url))
     
     response_data = {
         "url": url,
         "model1": result_model1,
         "model2": result_model2
     }
     
     return convert_numpy_to_python_types(response_data)
