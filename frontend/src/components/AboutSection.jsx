import React from 'react';
import {
  Info,
  Code2,
  Cpu,
  Database,
  Globe,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Award,
  ExternalLink,
  Radio,
  Sparkles,
} from 'lucide-react';

export function AboutSection({ healthData }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Title Card */}
      <div className="glass-panel" style={{ padding: '2.2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
          <Info size={28} style={{ color: 'var(--accent-blue)' }} />
          <h2>About CyberShield — Tri-Pillar Hybrid Phishing Detector</h2>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '1.02rem', lineHeight: '1.65' }}>
          CyberShield is an enterprise-grade cybersecurity web application integrating genuine machine-learning inference,
          threat intelligence telemetry, and optional secondary AI adjudication.
          Engineered using Java 21, Spring Boot, React, and MySQL, CyberShield enforces rigorous passive analysis,
          credential parameter redaction, and transparent evidence arbitration without blind score averaging.
        </p>
      </div>

      {/* Interactive Architecture Flow */}
      <div className="glass-panel" style={{ padding: '2rem' }}>
        <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Layers size={20} style={{ color: 'var(--accent-blue)' }} />
          Tri-Pillar Hybrid Detection Pipeline
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.92rem', marginBottom: '1.5rem' }}>
          Strictly engineered according to the required stack: React JS on Vercel, Java Spring Boot backend,
          embedded ONNX Runtime, Google Web Risk Threat Intelligence, Google Gemini API, and MySQL persistence.
        </p>

        <div className="arch-flow-box">
          <div className="arch-node">
            <Globe size={24} style={{ color: 'var(--accent-blue)' }} />
            <span className="arch-node-title">React 18 Frontend</span>
            <span className="arch-node-sub">Vite + Vanilla CSS</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Vercel Edge Host</span>
          </div>

          <div className="arch-arrow">→</div>

          <div className="arch-node">
            <Code2 size={24} style={{ color: 'var(--accent-cyan)' }} />
            <span className="arch-node-title">Spring Boot 3.3</span>
            <span className="arch-node-sub">Java 21 LTS REST API</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Validation & Redaction</span>
          </div>

          <div className="arch-arrow">→</div>

          <div className="arch-node" style={{ border: '1.5px solid rgba(56, 189, 248, 0.4)' }}>
            <div style={{ display: 'flex', gap: '6px', justifyContent: 'center' }}>
              <Cpu size={18} style={{ color: '#a855f7' }} />
              <Radio size={18} style={{ color: 'var(--accent-blue)' }} />
              <Sparkles size={18} style={{ color: '#ec4899' }} />
            </div>
            <span className="arch-node-title">Hybrid Orchestrator</span>
            <span className="arch-node-sub">ONNX + Threat + Gemini</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Evidence Rules</span>
          </div>

          <div className="arch-arrow">→</div>

          <div className="arch-node">
            <Database size={24} style={{ color: 'var(--color-legit)' }} />
            <span className="arch-node-title">MySQL 8.0</span>
            <span className="arch-node-sub">Spring Data JPA</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Audit History</span>
          </div>
        </div>
      </div>

      {/* Technology Stack Breakdown */}
      <div className="edu-grid">
        <div className="glass-panel edu-card">
          <h3 style={{ color: 'var(--accent-blue)' }}>
            <Code2 size={20} />
            Backend & Security
          </h3>
          <ul className="checklist">
            <li><span><strong>Language:</strong> Java 21 (OpenJDK / JBR)</span></li>
            <li><span><strong>Framework:</strong> Spring Boot 3.3.4 with Spring Web & Validation</span></li>
            <li><span><strong>Build Tool:</strong> Apache Maven 3.9.6 with Maven Wrapper (<code>./mvnw</code>)</span></li>
            <li><span><strong>Data Minimization:</strong> Automatic redaction of sensitive query tokens (keys, tokens, passwords)</span></li>
            <li><span><strong>Passive Analysis:</strong> Submitted URLs are strictly parsed and evaluated; never fetched or visited</span></li>
          </ul>
        </div>

        <div className="glass-panel edu-card">
          <h3 style={{ color: '#a855f7' }}>
            <Cpu size={20} />
            Pillar 1: ONNX ML Model
          </h3>
          <ul className="checklist">
            <li><span><strong>Source:</strong> Hugging Face (<code>pirocheto/phishing-url-detection</code>)</span></li>
            <li><span><strong>Engine:</strong> Microsoft ONNX Runtime Java (<code>1.19.2</code>)</span></li>
            <li><span><strong>Classifier:</strong> Scikit-Learn LinearSVM Pipeline with TF-IDF Vectorizer</span></li>
            <li><span><strong>Publisher Metric:</strong> 94.86% Reported Accuracy on static test set</span></li>
            <li><span><strong>Evaluation Note:</strong> Lexical-only model can exhibit false positives on brand names (e.g. <code>chatgpt.com</code>)</span></li>
          </ul>
        </div>

        <div className="glass-panel edu-card">
          <h3 style={{ color: 'var(--accent-cyan)' }}>
            <Radio size={20} />
            Pillar 2: Threat Intelligence
          </h3>
          <ul className="checklist">
            <li><span><strong>Provider:</strong> Google Web Risk API (or replaceable threat feed)</span></li>
            <li><span><strong>Threat Categories:</strong> Social Engineering, Malware, Unwanted Software</span></li>
            <li><span><strong>Priority:</strong> Confirmed matches immediately override ML to CRITICAL</span></li>
            <li><span><strong>Caveat:</strong> Negative lookup signifies absence of reported signature, NOT proof of safety</span></li>
            <li><span><strong>Status Handling:</strong> Unconfigured or timed out feeds degrade gracefully to NOT_CONFIGURED or UNAVAILABLE</span></li>
          </ul>
        </div>

        <div className="glass-panel edu-card">
          <h3 style={{ color: '#ec4899' }}>
            <Sparkles size={20} />
            Pillar 3: Google Gemini API
          </h3>
          <ul className="checklist">
            <li><span><strong>Model:</strong> Google Gemini 3.8 Flash (configurable via <code>GEMINI_MODEL</code>, default: <code>gemini-3.8-flash</code>)</span></li>
            <li><span><strong>Role:</strong> Secondary qualitative analysis on sanitized lexical tokens. Never treated as proof of safety alone.</span></li>
            <li><span><strong>Quota Strategy:</strong> Triggered conditionally on uncertain ML results or heuristic conflicts</span></li>
            <li><span><strong>Security Directive:</strong> Untrusted data isolation; instructed never to execute URL text</span></li>
            <li><span><strong>Output:</strong> Constrained JSON schema validated strictly in Java</span></li>
          </ul>
        </div>
      </div>

      {/* Live System Diagnostics */}
      {healthData && (
        <div className="glass-panel" style={{ padding: '1.8rem' }}>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Award size={20} style={{ color: 'var(--accent-blue)' }} />
            Live System Diagnostics
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
            <div style={{ background: 'rgba(7, 11, 19, 0.6)', padding: '0.85rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Overall Health</span>
              <div style={{ fontWeight: 700, color: 'var(--color-legit)' }}>{healthData.status}</div>
            </div>
            <div style={{ background: 'rgba(7, 11, 19, 0.6)', padding: '0.85rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>ONNX ML Engine</span>
              <div style={{ fontWeight: 700, color: 'var(--accent-blue)' }}>{healthData.modelStatus}</div>
            </div>
            <div style={{ background: 'rgba(7, 11, 19, 0.6)', padding: '0.85rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>MySQL Database</span>
              <div style={{ fontWeight: 700, color: 'var(--color-legit)' }}>{healthData.databaseStatus}</div>
            </div>
            <div style={{ background: 'rgba(7, 11, 19, 0.6)', padding: '0.85rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>ML Model Version</span>
              <div style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: '0.85rem' }}>{healthData.modelVersion}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
