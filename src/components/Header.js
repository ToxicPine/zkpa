import React from 'react';
import logoImage from '../assets/icon.png'; // Ensure the path to your image is correct

const Header = () => {
  return (
    <header className="bg-gray-800 py-1">
      <div className="container mx-auto flex items-center justify-between">
        <div className="flex items-center">
          {/* Use img tag with the imported logo image */}
          <img src={logoImage} alt="ZKPA Logo" className="h-16" />
        </div>
        <nav>
          <ul className="flex space-x-4">
            <li>
              <a href="#" className="text-gray-300 hover:text-white">
                Home
              </a>
            </li>
            <li>
              <a href="#" className="text-gray-300 hover:text-white">
                About
              </a>
            </li>
            <li>
              <a href="#" className="text-gray-300 hover:text-white">
                Contact
              </a>
            </li>
          </ul>
        </nav>
      </div>
    </header>
  );
};

export default Header;
