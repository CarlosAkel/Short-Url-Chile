import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import Cookies from "js-cookie";
import '../css/inputUrl.css'
import MAINURL from './ApiConfig';

function LoggedPage() {
    const [urlList, setUrlList] = useState([]);
    const [url, setUrl] = useState('');
    const navigate = useNavigate();

    const get_urls = async () => {
            
        const token = Cookies.get("access_token");
        const config = {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        };
        try {
            const response = await axios.get(`${MAINURL}/url/user`, config);
            setUrlList(response.data.short_url);
        } catch (error) {
            console.error('Error:', error);
        }
    }

    useEffect(() => {
        get_urls();
    }, []);
    

    async function url_user() {
        const formData = new FormData();
        const token = Cookies.get("access_token");
        formData.append('url', url);
        const config = {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        };
          
        try {
          const response = await axios.post(`${MAINURL}/url/user`, formData, config);
          get_urls();
          setUrl("");
          //localStorage.setItem("url", response.data.short_url);
          //navigate('/show');
        } catch (error) {
          console.error('Error:', error);
        }
      }





    return (
        <div >
            <div className="url">
                <p>Shorten Your Url </p>
                <input placeholder="Your Url" className="url-input" name="url" type="url" onChange={(e) => setUrl(e.target.value)} />
                <br />
                <div className="submit-btn" onClick={url_user} >SUBMIT</div>
            </div>
            {urlList.length > 0 && urlList.map((url, index) => (
                <a key={index} className='card' href={url} target="_blank">
                    {url}
                </a>
            ))}
        </div>
    );
}

export default LoggedPage;
