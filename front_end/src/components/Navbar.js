import React from 'react';
import '../css/navbar.css';
import { Link } from 'react-router-dom';

const Navbar = () => {
  return (
    <div className="navbar">
      <div className="start-button">
        <div className="start-button-icon"></div>
        <Link to="/" className="start-button-text">Start</Link>
      </div>
    </div>
  );
};

export default Navbar;
