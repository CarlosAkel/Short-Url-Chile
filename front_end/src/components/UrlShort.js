
import '../css/inputUrl.css'
import '../css/button.css'
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
function UrlShort() {

  const MAINURL = "http://localhost:8000"
  const [url, setUrl] = useState('');
  const navigate = useNavigate();

  async function url_guest() {
    const formData = new FormData();
    formData.append('url', url);
    try {
      const response = await axios.post(`${MAINURL}/url/guest`, formData);
      localStorage.setItem("url",response.data.short_url)
      navigate('/show');
    } catch (error) {
      console.error('Error:', error);
    }
  }


  return (
    <div>
      <div className="url">
        <p>Shorten Your Url </p>
        <input placeholder="Your Url" className="url-input" name="url" type="url" onChange={(e) => setUrl(e.target.value)} />
        <br />
        <div className="submit-btn" onClick={url_guest} >SUBMIT</div>
      </div>

      <div className="card">
        <div>Here you can login and obtain the list of your Urls</div>
        <div></div>
        <button className='button_class'>
          Login
        </button>
      </div>
    </div>
  );
}

export default UrlShort;
