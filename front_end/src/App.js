
import UrlShort from './components/UrlShort';
import ShowUrl from './components/ShowUrl';
import Login from './components/Login';
import SignUp from './components/SignUp';
import LoggedPage from './components/LoggedPage';
import './App.css'
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Navbar from './components/Navbar';
import PasswordReset from './components/PasswordReset';
import PasswordResetMailLinkSend from './components/PasswordResetMailLinkSend';
function App() {
  return (
    <div>
     
      
      <BrowserRouter>
      <Navbar />
      <div className="app-container">
        <Routes>
          <Route path="/" element={<UrlShort />} />
          <Route path="/show" element={<ShowUrl />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<SignUp />} />
          <Route path="/urls" element={<LoggedPage />} />
          <Route path="/reset-password" element={<PasswordReset />} />
          <Route path="/change-password" element={<PasswordResetMailLinkSend />} />
        </Routes>
        </div>
      </BrowserRouter>
    </div>


  );
}



export default App;
