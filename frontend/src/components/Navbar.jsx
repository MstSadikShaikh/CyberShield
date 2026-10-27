import React from 'react';
import { Shield, Activity, ShieldCheck, History, BookOpen, Info, ExternalLink } from 'lucide-react';

export function Navbar({ activeTab, setActiveTab, healthData, isScanning }) {
  const isOnline = healthData && healthData.status === 'UP';

  return (
    <header className="navbar">
      <div className="navbar-inner">
        <div className="brand-wrapper" onClick={() => setActiveTab('scanner')}>
          <div className="brand-icon-box">
            <Shield size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <span className="brand-title">CyberShield</span>
              <span className="brand-tag">ML-v1.0</span>
            </div>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-dim)', letterSpacing: '0.02em' }}>
              Phishing URL Detection System
            </p>
          </div>
        </div>

        <nav>
          <ul className="nav-links">
            <li>
              <button
                className={`nav-btn ${activeTab === 'scanner' ? 'active' : ''}`}
                onClick={() => setActiveTab('scanner')}
              >
                <ShieldCheck size={17} />
                <span>Scanner</span>
              </button>
            </li>
            <li>
              <button
                className={`nav-btn ${activeTab === 'results' ? 'active' : ''}`}
                onClick={() => setActiveTab('results')}
              >
                <Activity size={17} />
                <span>Results</span>
              </button>
            </li>
            <li>
              <button
                className={`nav-btn ${activeTab === 'history' ? 'active' : ''}`}
                onClick={() => setActiveTab('history')}
              >
                <History size={17} />
                <span>Audit Log</span>
              </button>
            </li>
            <li>
              <button
                className={`nav-btn ${activeTab === 'education' ? 'active' : ''}`}
                onClick={() => setActiveTab('education')}
              >
                <BookOpen size={17} />
                <span>Education</span>
              </button>
            </li>
            <li>
              <button
                className={`nav-btn ${activeTab === 'about' ? 'active' : ''}`}
                onClick={() => setActiveTab('about')}
              >
                <Info size={17} />
                <span>About</span>
              </button>
            </li>
          </ul>
        </nav>

        <div className="status-pill" title={isOnline ? 'Spring Boot & ONNX Runtime Connected' : 'Backend Disconnected'}>
          <span className={`status-dot ${isOnline ? 'online' : 'offline'}`} />
          <span style={{ color: isOnline ? 'var(--color-legit)' : 'var(--color-phish)' }}>
            {isOnline ? 'Core: Online' : 'Core: Standby'}
          </span>
        </div>
      </div>
    </header>
  );
}
