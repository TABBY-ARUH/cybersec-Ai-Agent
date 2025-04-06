// src/main.jsx
import React from "react";
import ReactDOM from "react-dom/client";
import CyberSecAgent from "./App";
import "./index.scss"; // Make sure this file exists and contains your Tailwind or custom styles
import 'tw-animate-css';

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <CyberSecAgent />
  </React.StrictMode>
);

