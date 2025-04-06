import React from "react";
import ReactDOM from "react-dom";
import "./src/index.scss"; // Ensure correct path based on your structure
import CyberSecApp from "./src/App";
import "./tailwind.css";



ReactDOM.render(
  <React.StrictMode>
    <CyberSecApp />
  </React.StrictMode>,
  document.getElementById("root")
);
