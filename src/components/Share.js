import React from 'react';
import { FaTwitter, FaFacebookF, FaInstagram, FaLinkedinIn, FaYoutube } from 'react-icons/fa';

const Share = ({ iconSize = 40 }) => {
  return (
    <div className="flex justify-center items-center space-x-4 bg-gray-900 p-2 pb-20">
      <a href="https://twitter.com" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-gray-200">
        <FaTwitter size={iconSize} />
      </a>
      <a href="https://facebook.com" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-gray-200">
        <FaFacebookF size={iconSize} />
      </a>
      <a href="https://instagram.com" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-gray-200">
        <FaInstagram size={iconSize} />
      </a>
      <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-gray-200">
        <FaLinkedinIn size={iconSize} />
      </a>
      <a href="https://youtube.com" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-gray-200">
        <FaYoutube size={iconSize} />
      </a>
    </div>
  );
};

export default Share;
