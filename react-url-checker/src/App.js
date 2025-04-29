// src/App.js
import React from "react";
import UrlPredictor from "./components/UrlPredictor";
import './App.css';

function App() {
  return (
<div className="min-h-screen bg-gray-100 flex flex-col justify-center">
  <div className="container mx-auto px-4 text-center">
    <h1 className="text-3xl font-bold text-blue-600 mb-6">🔍 악성 URL 판별기</h1>
    <UrlPredictor />
  </div>
</div>

  );
}

export default App;
