import React, { useState, useEffect } from 'react';
import { Shield, Search, X, AlertTriangle, ArrowRight, CheckCircle2, Lock, Cpu, Database, EyeOff } from 'lucide-react';

const DEMO_URLS = [
  {
    label: 'Google (Legitimate)',
    url: 'https://www.google.com',
    type: 'legit',
  },
  {
    label: 'ChatGPT (Conflict Adjudication)',
    url: 'https://chatgpt.com',
    type: 'uncertain',
  },
  {
    label: 'Medical News (Legitimate)',
    url: 'http://www.medicalnewstoday.com/articles/188939.php',
    type: 'legit',
  },
  {
    label: 'PayPal Impersonator (Phishing)',
    url: 'http://paypal-security-update-account.com/login',
    type: 'phish',
  },
  {
    label: 'Credential Harvester (Phishing)',
    url: 'https://clubedemilhagem.com/home.php',
    type: 'phish',
  },
];

const SCAN_STEPS = [
  'Validating URL syntax and redacting sensitive credentials...',
  'Extracting structural features, domain depth, and Shannon entropy...',
  'Executing ONNX Runtime Java inference with pretrained LinearSVM...',
  'Checking Google Web Risk threat intelligence signatures...',
  'Evaluating evidence conflicts and invoking Gemini AI secondary review...',
  'Calibrating risk matrix and recording audit trail to MySQL...',
];

export function UrlScanner({ onScan, isScanning, error, lastScannedUrl }) {
  const [inputUrl, setInputUrl] = useState(lastScannedUrl || '');
  const [currentStepIdx, setCurrentStepIdx] = useState(0);
  const [validationErr, setValidationErr] = useState('');

  // Cycle through animation steps while scanning is active
  useEffect(() => {
    if (!isScanning) {
      setCurrentStepIdx(0);
      return;
    }
    const interval = setInterval(() => {
      setCurrentStepIdx((prev) => (prev + 1) % SCAN_STEPS.length);
    }, 450);
    return () => clearInterval(interval);
  }, [isScanning]);

  const handleSubmit = (e) => {
    e.preventDefault();
    setValidationErr('');

    const trimmed = inputUrl.trim();
    if (!trimmed) {
      setValidationErr('Please enter a website URL to scan.');
      return;
    }

    // Client-side quick check
    if (trimmed.startsWith('file:') || trimmed.startsWith('javascript:') || trimmed.startsWith('data:')) {
      setValidationErr('Unsupported protocol. Only HTTP and HTTPS addresses are permitted.');
      return;
    }

    onScan(trimmed);
  };

  const selectDemo = (url) => {
    setInputUrl(url);
    setValidationErr('');
  };

  return (
    <div>
      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-badge">
          <Shield size={14} />
          <span>Tri-Pillar Hybrid Phishing Detection Gateway</span>
        </div>
        <h1 className="hero-title">
          Stay One Step Ahead <br />
          <span className="gradient-text">of Phishing Threats</span>
        </h1>
        <p className="hero-subtitle">
          Instantly evaluate suspicious links with tri-pillar hybrid detection.
          Powered by Java 21 Spring Boot, local ONNX Runtime inference, Google Web Risk threat intelligence, Google Gemini AI secondary review, and persistent MySQL audit logging.
        </p>
      </section>

      {/* Main Scanner Card */}
      <div className="glass-panel scanner-card">
        <form onSubmit={handleSubmit} className="scanner-form">
          <div className="input-group">
            <Search className="input-icon" size={20} />
            <input
              type="text"
              className="url-input"
              placeholder="Paste or type suspicious URL (e.g., https://example-verification.com/login)..."
              value={inputUrl}
              onChange={(e) => {
                setInputUrl(e.target.value);
                if (validationErr) setValidationErr('');
              }}
              disabled={isScanning}
              autoFocus
            />
            {inputUrl && !isScanning && (
              <button
                type="button"
                className="clear-btn"
                onClick={() => setInputUrl('')}
                title="Clear input"
              >
                <X size={18} />
              </button>
            )}
          </div>

          <button
            type="submit"
            className="scan-submit-btn"
            disabled={isScanning || !inputUrl.trim()}
          >
            {isScanning ? (
              <>
                <div
                  style={{
                    width: '18px',
                    height: '18px',
                    border: '2px solid rgba(7, 11, 19, 0.4)',
                    borderTopColor: '#070b13',
                    borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite',
                  }}
                />
                <span>Analyzing URL via ONNX Engine...</span>
              </>
            ) : (
              <>
                <span>Scan URL</span>
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        {/* Client or Server Error */}
        {(validationErr || error) && (
          <div
            style={{
              marginTop: '1.2rem',
              padding: '0.85rem 1.1rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              color: '#f87171',
              fontSize: '0.92rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.65rem',
            }}
          >
            <AlertTriangle size={18} style={{ flexShrink: 0 }} />
            <span>{validationErr || error}</span>
          </div>
        )}

        {/* Scan In Progress Animation */}
        {isScanning && (
          <div className="scan-progress-box">
            <div className="progress-bar-track">
              <div
                className="progress-bar-fill"
                style={{ width: `${((currentStepIdx + 1) / SCAN_STEPS.length) * 100}%` }}
              />
            </div>
            <div className="progress-step-text">
              <Cpu size={16} />
              <span>{SCAN_STEPS[currentStepIdx]}</span>
            </div>
          </div>
        )}

        {/* Quick Demo URLs */}
        <div style={{ marginTop: '1.8rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '1.2rem' }}>
          <div className="demo-links-bar">
            <span style={{ fontWeight: 600, color: 'var(--text-dim)' }}>Try Samples:</span>
            {DEMO_URLS.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                className="demo-chip"
                onClick={() => selectDemo(demo.url)}
                disabled={isScanning}
                title={`Click to fill: ${demo.url}`}
              >
                {demo.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Defensive Security Guarantee */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          background: 'rgba(0, 240, 255, 0.04)',
          border: '1px solid rgba(0, 240, 255, 0.12)',
          borderRadius: 'var(--radius-md)',
          padding: '1rem 1.25rem',
          fontSize: '0.85rem',
          color: 'var(--text-muted)',
          maxWidth: '840px',
          margin: '0 auto',
        }}
      >
        <EyeOff size={22} style={{ color: 'var(--accent-blue)', flexShrink: 0 }} />
        <span>
          <strong>Defensive Safety Guarantee:</strong> CyberShield is an educational, passive classification tool.
          It performs algorithmic and neural lexical inspection of URL structures. It <em>never</em> automatically
          fetches, navigates to, or executes any content from the submitted URL.
        </span>
      </div>

      {/* Feature Highlights Grid */}
      <div className="features-grid">
        <div className="glass-panel feature-card">
          <div className="feature-icon-wrapper">
            <Cpu size={24} />
          </div>
          <h3 className="feature-title">Pretrained ML Engine</h3>
          <p className="feature-desc">
            Uses a genuine linear SVM model trained on over 100,000 verified malicious and benign URLs, exported to ONNX
            format and executed natively in Java without external Python microservices.
          </p>
        </div>

        <div className="glass-panel feature-card">
          <div className="feature-icon-wrapper">
            <Shield size={24} />
          </div>
          <h3 className="feature-title">Multi-Signal Heuristics</h3>
          <p className="feature-desc">
            Evaluates Shannon entropy for DGA detection, IP address host spoofing, embedded '@' credential deception,
            excessive subdomains, and suspicious TLD patterns.
          </p>
        </div>

        <div className="glass-panel feature-card">
          <div className="feature-icon-wrapper">
            <Database size={24} />
          </div>
          <h3 className="feature-title">Persistent MySQL Audit</h3>
          <p className="feature-desc">
            Every inspection is indexed and archived with UTC timestamps in a production MySQL database, with sensitive
            credentials and token parameters automatically redacted before storage.
          </p>
        </div>
      </div>
    </div>
  );
}
