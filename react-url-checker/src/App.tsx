// App.tsx
import UrlPredictor from './components/UrlPredictor';

function App() {
  return (
    <div>
      <h1 className="text-4xl text-red-500 font-bold">Hello Tailwind!</h1>
      <h1>URL 악성 여부 판별기</h1>
      <UrlPredictor />
    </div>
  );
}

export default App;
