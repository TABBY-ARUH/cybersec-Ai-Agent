import React from 'react';
import ReactDOM from 'react-dom';
import './index.scss';  // Assuming you're using SCSS for styles
import CyberSecApp from './src/App';  // Adjust the path if necessary

// Render the app component into the root element
ReactDOM.render(
  <React.StrictMode>
    <CyberSecApp />
  </React.StrictMode>,
  document.getElementById('root')
);
