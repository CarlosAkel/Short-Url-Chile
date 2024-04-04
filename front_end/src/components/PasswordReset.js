import React, { useState, useEffect } from 'react';
import axios from 'axios';
import MAINURL from './ApiConfig';
import '../css/login-sign.css'

export default function PasswordReset() {

    const [email, setEmail] = useState("")

    async function send_reset()
    {
        const formData = new FormData();
        formData.append('email', email);
        try {
          const response = await axios.post(`${MAINURL}/forgot-password`, formData);
          console.log(response)
          //localStorage.setItem("url", response.data.short_url)
          //navigate('/show');
        } catch (error) {
          console.error('Error:', error);
        }
    }

    return(
        <div>
        <div className='card'>
            TEST RESET
            <input type='email' onChange={(e) => setEmail(e.target.value)} placeholder="Email"></input>
            <button onClick={send_reset}>RESET</button>
        </div>
        </div>

    )
}