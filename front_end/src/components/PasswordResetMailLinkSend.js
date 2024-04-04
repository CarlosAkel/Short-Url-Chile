import React, { useState, useEffect } from 'react';
import axios from 'axios';
import MAINURL from './ApiConfig';
import { useNavigate } from 'react-router-dom';
import Cookies from "js-cookie";
import '../css/login-sign.css'
export default function PasswordResetMailLinkSend() {

    const [password, setPassword] = useState("")
    const navigate = useNavigate();

    async function reset_password() {
        const formData = new FormData();
        formData.append('new_password', password);
        try {
            const token = Cookies.get("access_token");
            const config = {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            };
            const response = await axios.post(`${MAINURL}/reset-password`, formData, config);
            console.log(response)
            navigate('/');
        } catch (error) {
            console.error('Error:', error);
        }
    }
    return (
        <div>
        <div className='card'>
            TEST PASSWORD
            <input type='email' onChange={(e) => setPassword(e.target.value)} placeholder="Email"></input>
            <button onClick={reset_password}>RESET</button>
        </div>
        </div>
    )
}