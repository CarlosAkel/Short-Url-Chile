
import UrlShort from './components/UrlShort';
import ShowUrl from './components/ShowUrl';
import './App.css'
import { BrowserRouter, Routes, Route } from "react-router-dom";
function App() {
  return (
    <div className="app-container">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<UrlShort />} />
          <Route path="/show" element={<ShowUrl />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;
