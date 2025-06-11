# URL Malicious Detection API

This FastAPI application provides an API for detecting malicious URLs using two different machine learning models.

## Features

- Two independent ML models for URL analysis
- RESTful API for easy integration
- High performance with `uv` package management

## Installation

1. Clone the repository
2. Create and activate a virtual environment using `uv`:

```bash
cd backend
uv venv
source .venv/bin/activate
```

3. Install dependencies using `uv pip`:

```bash
uv pip install -r requirements.txt
```

## Running the Application

Start the FastAPI server:

```bash
uvicorn app.main:app --reload
```

The API will be available at http://localhost:8000

## API Endpoints

### GET /

Health check endpoint that confirms the API is running.

**Response**:
```json
{
  "message": "URL 악성 판별기 FastAPI 서버 정상 작동 중!"
}
```

### POST /predict

Analyzes a URL to determine if it's malicious.

**Request Body**:
```json
{
  "url": "http://example.com"
}
```

**Response**:
```json
{
  "url": "http://example.com",
  "model1": 0.2048,  // Lower value means less likely to be malicious
  "model2": {
    "url": "http://example.com",
    "malicious_probability": 0.1076,  // Probability of being malicious
    "is_malicious": false,  // Boolean classification result
    "threshold": 0.4034  // Classification threshold
  }
}
```

## Models

The application uses two different models for URL analysis:

1. **XGBoost Ensemble** (model1): Ensemble of 4 XGBoost models
2. **Neural Network** (model2): TensorFlow/Keras model

## Dependencies

Main dependencies:
- FastAPI
- TensorFlow
- XGBoost
- scikit-learn
- pandas
- numpy
- tldextract
- uvicorn

## License

This project is licensed under the MIT License.
