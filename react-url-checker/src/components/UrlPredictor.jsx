import React, { useState } from "react";
import axios from "axios";

const UrlPredictor = () => {
  const [url, setUrl] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResults(null);

    try {
      const response = await axios.post("http://34.64.139.6:8000/predict", {
        url: url,
      });
      setResults(response.data);
    } catch (err) {
      console.error(err);
      setError("서버 오류가 발생했습니다.");
    } finally {
      setLoading(false);
    }
  };

  // 모델 정보 정의 (title + 키)
  const models = [
    { key: "old_model", title: "🧠 기존 모델 (Ho)" },
    { key: "new_model", title: "🚀 개선 모델 (Jun)" },
  ];

  return (
    <div className="min-h-screen bg-gray-100 p-6">
      {!results ? (
        <div className="flex justify-center items-center h-full">
          <form onSubmit={handleSubmit} className="flex gap-4 w-full max-w-2xl">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="URL을 입력하세요"
              className="flex-grow px-4 py-2 border border-gray-300 rounded shadow"
              required
            />
            <button
              type="submit"
              className="bg-blue-600 text-white px-6 py-2 rounded shadow hover:bg-blue-700 transition"
            >
              ✅ 검사하기
            </button>
          </form>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-6">
          {/* 좌측 입력창 */}
          <div className="flex flex-col gap-4">
            <form onSubmit={handleSubmit} className="flex gap-2">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-grow px-4 py-2 border border-gray-300 rounded shadow"
                placeholder="URL을 다시 입력해보세요"
                required
              />
              <button
                type="submit"
                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition"
              >
                다시 검사
              </button>
            </form>
            {loading && <p>🔍 분석 중...</p>}
            {error && <p className="text-red-500">❌ {error}</p>}
          </div>

          {/* 우측 결과 반복 렌더링 */}
          <div className="flex flex-col gap-4">
            {models.map((model) => {
              const data = results[model.key];
              return (
                <div key={model.key} className="bg-white rounded p-4 shadow">
                  <h2 className="text-lg font-bold mb-2">{model.title}</h2>
                  <p>
                    악성 확률: <strong>{(data.prob * 100).toFixed(2)}%</strong>
                  </p>
                  <p>
                    판별 결과:{" "}
                    <strong className={data.malicious ? "text-red-600" : "text-green-600"}>
                      {data.malicious ? "⚠️ 악성 URL" : "✅ 정상 URL"}
                    </strong>
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default UrlPredictor;
