import React from 'react';
import { Shield, Lock, Code2, Heart } from 'lucide-react';

export function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <Shield size={20} style={{ color: 'var(--accent-blue)' }} />
          <span style={{ fontWeight: 800, fontSize: '1.1rem', letterSpacing: '-0.02em' }}>CyberShield</span>
          <span style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>— Defensive AI Security Gateway</span>
        </div>

        <p className="footer-disclaimer">
          CyberShield is an educational, defensive cybersecurity application designed to assist users in detecting
          potential phishing indicators through pretrained machine-learning inference. It operates passively and never
          interacts with or retrieves remote webpage content.
        </p>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', justifyContent: 'center' }}>
          <span className="badge-pill">Java 21</span>
          <span className="badge-pill">Spring Boot 3.3</span>
          <span className="badge-pill">ONNX Runtime Java</span>
          <span className="badge-pill">MySQL 8.0</span>
          <span className="badge-pill">React 18</span>
          <span className="badge-pill">Vite</span>
          <span className="badge-pill">Vercel Ready</span>
        </div>

        <div className="footer-meta">
          <span>College Microproject Submission &bull; MIT License &bull; No User Accounts Required</span>
        </div>
      </div>
    </footer>
  );
}
