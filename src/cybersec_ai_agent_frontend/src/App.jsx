import React, { useState } from 'react';
import './App.css';
import './index.scss';  

const App = () => {
  const [ip, setIp] = useState('');
  const [port, setPort] = useState(80);
  const [scanResult, setScanResult] = useState(null);
  const [threatInput, setThreatInput] = useState('');
  const [threatResponse, setThreatResponse] = useState([]);
  const [logs, setLogs] = useState([]);

  const detectThreats = async () => {
    const response = await fetch('/api/detect_threats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{ source: 'frontend', message: threatInput }]),
    });
    const data = await response.json();
    setThreatResponse(data);
  };

  const scanPort = async () => {
    const response = await fetch(`/api/scan_port?ip=${ip}&port=${port}`);
    const result = await response.json();
    setScanResult(`Port ${result.port} is ${result.open ? 'open' : 'closed'}`);
  };

  const getSecurityLogs = async () => {
    const response = await fetch('/api/get_security_logs');
    const data = await response.json();
    setLogs(data);
  };

  return (
    <div className="app-container">
      <h1>CyberSec AI Agent 🛡️</h1>

      <section className="card">
        <h2>Threat Detection</h2>
        <textarea
          rows={4}
          value={threatInput}
          onChange={(e) => setThreatInput(e.target.value)}
          placeholder="Enter a suspicious message"
        />
        <button onClick={detectThreats}>Detect Threat</button>
        {threatResponse.length > 0 && (
          <div className="response-box">
            {threatResponse.map((t, i) => (
              <p key={i}>
                {t.details} | Category: {t.category} | Confidence: {t.confidence}
              </p>
            ))}
          </div>
        )}
      </section>

      <section className="card">
        <h2>Port Scanner</h2>
        <input
          type="text"
          placeholder="IP Address"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
        />
        <input
          type="number"
          placeholder="Port"
          value={port}
          onChange={(e) => setPort(parseInt(e.target.value))}
        />
        <button onClick={scanPort}>Scan Port</button>
        {scanResult && <p>{scanResult}</p>}
      </section>

      <section className="card">
        <h2>Security Logs</h2>
        <button onClick={getSecurityLogs}>Get Logs</button>
        <ul>
          {logs.map((log, i) => (
            <li key={i}>
              [{new Date(log.timestamp / 1_000_000).toLocaleString()}] {log.event_type} -{' '}
              {log.severity}: {log.details}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
};

export default App;
