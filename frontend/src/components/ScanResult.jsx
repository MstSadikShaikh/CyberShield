import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  HelpCircle,
  Copy,
  Check,
  RefreshCw,
  Clock,
  Cpu,
  Layers,
  AlertTriangle,
  CheckCircle,
  Info,
  Radio,
  Sparkles,
  ShieldX,
  ShieldQuestion,
  FileText,
  AlertOctagon,
  Eye,
  CheckCircle2,
} from 'lucide-react';

export function ScanResult({ scanData, onScanAgain }) {
  const [copied, setCopied] = useState(false);

  if (!scanData) {
    return (
      <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center' }}>
        <HelpCircle size={48} style={{ color: 'var(--text-dim)', marginBottom: '1rem' }} />
        <h2>No Scan Results Selected</h2>
        <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', marginBottom: '1.5rem' }}>
          Please submit a URL in the Scanner or select an entry from the Audit Log.
        </p>
        <button className="scan-submit-btn" style={{ margin: '0 auto' }} onClick={onScanAgain}>
          Go to Scanner
        </button>
      </div>
    );
  }

  const {
    id,
    submittedUrl,
    sanitizedUrl,
    prediction,
    riskScore = 0,
    riskLevel = 'LOW',
    modelVersion,
    modelProbability,
    modelAssessment,
    finalAssessment,
    explanation,
    precautions = [],
    indicators = [],
    limitations = [],
    threatIntelligence,
    geminiAnalysis,
    scannedAt,
  } = scanData;

  const handleCopy = () => {
    navigator.clipboard.writeText(submittedUrl || sanitizedUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isPhish = prediction === 'PHISHING';
  const isLegit = prediction === 'LEGITIMATE';
  const isUncertain = prediction === 'UNCERTAIN';
  const statusClass = isPhish ? 'phish' : isLegit ? 'legit' : 'uncertain';

  // SVG circular progress calculation (Radius 50 -> circumference ~ 314.159)
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - ((riskScore || 0) / 100) * circumference;

  const formatProbability = (prob) => {
    if (prob === null || prob === undefined) return 'N/A';
    return `${(prob * 100).toFixed(1)}%`;
  };

  // Helper for final assessment label
  const getFinalAssessmentBadge = () => {
    switch (finalAssessment) {
      case 'CONFIRMED_THREAT':
        return { label: 'Confirmed Threat Signature', color: '#ff6b6b', bg: 'rgba(239, 68, 68, 0.2)' };
      case 'HIGH_RISK_ML':
        return { label: 'High-Risk ML Indicator', color: '#ff6b6b', bg: 'rgba(239, 68, 68, 0.2)' };
      case 'CONFLICT_EVIDENCE_UNCERTAIN':
        return { label: 'Conflict Documented (Conservative Medium Risk)', color: '#fbbf24', bg: 'rgba(245, 158, 11, 0.2)' };
      case 'CONFLICT_UNRESOLVED':
        return { label: 'Conflict Unresolved: Conservative Medium Risk', color: '#fbbf24', bg: 'rgba(245, 158, 11, 0.2)' };
      case 'CONFLICT_RESOLVED_BENIGN':
        return { label: 'Conflict Documented (Legacy Benign)', color: '#34d399', bg: 'rgba(16, 185, 129, 0.2)' };
      case 'AI_ELEVATED':
        return { label: 'Elevated by Gemini AI (Phishing)', color: '#f87171', bg: 'rgba(239, 68, 68, 0.2)' };
      case 'AI_CONFIRMED_BENIGN':
        return { label: 'Consistent Clean Evidence', color: '#34d399', bg: 'rgba(16, 185, 129, 0.2)' };
      case 'LOW_RISK_LEGITIMATE':
        return { label: 'Low-Risk Standard Domain', color: '#34d399', bg: 'rgba(16, 185, 129, 0.2)' };
      default:
        return { label: finalAssessment || prediction, color: '#94a3b8', bg: 'rgba(255, 255, 255, 0.08)' };
    }
  };

  const finalBadge = getFinalAssessmentBadge();

  // Threat intelligence pill status
  const threatStatus = threatIntelligence?.status || 'NOT_CONFIGURED';
  const geminiStatus = geminiAnalysis?.status || 'NOT_CONFIGURED';
  const geminiAssessment = geminiAnalysis?.assessment || 'NOT_PERFORMED';

  const isConflict =
    finalAssessment === 'CONFLICT_EVIDENCE_UNCERTAIN' ||
    finalAssessment === 'CONFLICT_UNRESOLVED' ||
    finalAssessment === 'CONFLICT_RESOLVED_BENIGN';

  return (
    <div className="result-container">
      {/* Top Header Card */}
      <div className={`glass-panel result-header-card ${statusClass}`}>
        <div className="result-main-grid">
          {/* Circular Risk Score Gauge */}
          <div className="score-circle-wrapper">
            <svg viewBox="0 0 120 120" className="circular-chart">
              <circle className="circle-bg" cx="60" cy="60" r={radius} />
              <circle
                className={`circle-stroke ${statusClass}`}
                cx="60"
                cy="60"
                r={radius}
                strokeDasharray={`${circumference} ${circumference}`}
                style={{ strokeDashoffset }}
                transform="rotate(-90 60 60)"
              />
            </svg>
            <div className="gauge-center-text">
              <span className="gauge-number" style={{ color: isPhish ? '#ff6b6b' : isLegit ? '#34d399' : '#fbbf24' }}>
                {Math.round(riskScore)}
              </span>
              <span className="gauge-label">Risk Score</span>
            </div>
          </div>

          {/* Verdict Info */}
          <div className="verdict-info">
            <div className="badges-row">
              <span className={`prediction-badge ${statusClass}`}>
                {isPhish && <ShieldAlert size={20} />}
                {isLegit && <ShieldCheck size={20} />}
                {isUncertain && <HelpCircle size={20} />}
                <span>{prediction}</span>
              </span>

              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  padding: '0.4rem 0.85rem',
                  borderRadius: 'var(--radius-sm)',
                  background: finalBadge.bg,
                  color: finalBadge.color,
                  border: `1px solid ${finalBadge.color}40`,
                }}
              >
                {finalBadge.label}
              </span>

              <span className="level-badge">
                Level: <strong>{riskLevel}</strong>
              </span>

              {id && (
                <span className="level-badge" title="Database Record ID">
                  Audit ID: #{id}
                </span>
              )}
            </div>

            {/* URL Display */}
            <div className="url-display-bar">
              <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>Target:</span>
              <span style={{ flex: 1 }}>{submittedUrl || sanitizedUrl}</span>
              <button className="copy-btn" onClick={handleCopy} title="Copy URL">
                {copied ? <Check size={16} style={{ color: 'var(--color-legit)' }} /> : <Copy size={16} />}
              </button>
            </div>

            {/* Metadata Chips */}
            <div className="meta-stats-row">
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Cpu size={14} /> Model: {modelVersion || 'pirocheto-linear-svm-v1.0'}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Layers size={14} /> Uncalibrated Model Score: {formatProbability(modelProbability)}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Clock size={14} /> Scanned: {scannedAt ? new Date(scannedAt).toLocaleTimeString() : 'Just now'} UTC
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Disagreement / Conflict Banner */}
      {isConflict && (
        <div className={`conflict-callout ${finalAssessment === 'CONFLICT_RESOLVED_BENIGN' ? 'benign' : ''}`}>
          <div className="conflict-callout-header">
            <AlertOctagon
              size={18}
              style={{
                color:
                  finalAssessment === 'CONFLICT_RESOLVED_BENIGN'
                    ? 'var(--color-legit)'
                    : 'var(--color-uncertain)',
              }}
            />
            <span>
              {finalAssessment === 'CONFLICT_EVIDENCE_UNCERTAIN'
                ? 'Model Conflict Documented: Conservative Medium Risk (Defensive Safety Policy)'
                : finalAssessment === 'CONFLICT_UNRESOLVED'
                ? 'Model Conflict Documented (Disagreement Between ML & Heuristics)'
                : 'Model Conflict Documented'}
            </span>
          </div>
          <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: '1.55' }}>
            {finalAssessment === 'CONFLICT_EVIDENCE_UNCERTAIN'
              ? 'The pretrained statistical ML model flagged potential phishing, but zero structural threat indicators (IP host, obfuscation, deceptive subdomains) were detected and Gemini secondary AI observed no obvious malice. In accordance with strict defensive cybersecurity rules, a qualitative LLM opinion alone cannot prove a domain legitimate over a high ML signal. CyberShield conservatively reports UNCERTAIN.'
              : finalAssessment === 'CONFLICT_RESOLVED_BENIGN'
              ? 'The pretrained statistical ML model flagged potential phishing (likely due to short domain length or vocabulary absence), but zero heuristic threat indicators were detected and Gemini secondary AI verified clean domain syntax.'
              : 'The statistical ML model indicated risk, yet zero structural threat indicators (IP host, obfuscation, deceptive subdomains) were present. Because secondary AI verification was unconfigured, CyberShield refused to invent an arbitrary binary classification and classified this domain conservatively as UNCERTAIN.'}
          </p>
        </div>
      )}

      {/* Tri-Pillar Hybrid Detection Grid */}
      <div className="glass-panel result-section">
        <h3 className="section-heading">
          <Eye size={20} style={{ color: 'var(--accent-blue)' }} />
          Tri-Pillar Hybrid Assessment Breakdown
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
          CyberShield arbitrates evidence across three independent assessment pillars without blindly averaging disparate probabilities.
        </p>

        <div className="hybrid-pillars-grid">
          {/* Pillar 1: Pretrained ML Classifier */}
          <div className="pillar-card">
            <div className="pillar-header">
              <div className="pillar-title-group">
                <Cpu size={20} style={{ color: 'var(--accent-cyan)' }} />
                <div>
                  <div className="pillar-title">ONNX ML Classifier</div>
                  <div className="pillar-subtitle">Local Embedded Inference</div>
                </div>
              </div>
              <span className="pillar-badge active">Active (Local)</span>
            </div>

            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '3px' }}>Model Classification</div>
              <div className="pillar-metric">
                {modelAssessment || (modelProbability !== null ? `${formatProbability(modelProbability)} phish` : 'Executed')}
              </div>
            </div>

            <div className="pillar-desc">
              LinearSVM model trained on lexical and structural n-gram distributions. Operates in-process via Java ONNX Runtime without network roundtrips.
            </div>

            <div className="pillar-note">
              <strong>Provenance:</strong> 94.86% publisher accuracy on static evaluation sets. Does not reflect live real-world threat feeds.
            </div>
          </div>

          {/* Pillar 2: Threat Intelligence Feed */}
          <div className="pillar-card">
            <div className="pillar-header">
              <div className="pillar-title-group">
                <Radio size={20} style={{ color: threatStatus === 'MATCH_FOUND' ? '#ff6b6b' : 'var(--accent-blue)' }} />
                <div>
                  <div className="pillar-title">Threat Intelligence</div>
                  <div className="pillar-subtitle">{threatIntelligence?.source || 'Google Web Risk API'}</div>
                </div>
              </div>
              <span
                className={`pillar-badge ${
                  threatStatus === 'MATCH_FOUND'
                    ? 'match'
                    : threatStatus === 'NO_MATCH'
                    ? 'clean'
                    : threatStatus === 'UNAVAILABLE'
                    ? 'warn'
                    : 'dim'
                }`}
              >
                {threatStatus === 'MATCH_FOUND'
                  ? 'Threat Match'
                  : threatStatus === 'NO_MATCH'
                  ? 'No Signatures'
                  : threatStatus === 'UNAVAILABLE'
                  ? 'Unavailable'
                  : 'Not Configured'}
              </span>
            </div>

            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '3px' }}>Feed Status</div>
              <div
                className="pillar-metric"
                style={{
                  color: threatStatus === 'MATCH_FOUND' ? '#ff6b6b' : threatStatus === 'NO_MATCH' ? '#34d399' : 'var(--text-muted)',
                }}
              >
                {threatStatus === 'MATCH_FOUND'
                  ? 'CONFIRMED MATCH'
                  : threatStatus === 'NO_MATCH'
                  ? 'NO KNOWN MATCH'
                  : threatStatus === 'UNAVAILABLE'
                  ? 'FEED UNAVAILABLE'
                  : 'NOT CONFIGURED'}
              </div>
            </div>

            <div className="pillar-desc">
              {threatIntelligence?.details || 'Real-time blacklist and malware signature feed for known social engineering campaigns.'}
              {threatIntelligence?.threatMatches && threatIntelligence.threatMatches.length > 0 && (
                <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                  {threatIntelligence.threatMatches.map((t, i) => (
                    <span key={i} className="pillar-badge match" style={{ fontSize: '0.7rem' }}>
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="pillar-note">
              <strong>Caveat:</strong> A negative lookup ({threatStatus}) signifies absence of known signatures in public threat feeds; it does NOT prove the link is safe.
            </div>
          </div>

          {/* Pillar 3: Google Gemini Secondary AI */}
          <div className="pillar-card">
            <div className="pillar-header">
              <div className="pillar-title-group">
                <Sparkles size={20} style={{ color: '#a855f7' }} />
                <div>
                  <div className="pillar-title">Gemini AI Review</div>
                  <div className="pillar-subtitle">{geminiAnalysis?.providerModel || 'gemini-3.8-flash'}</div>
                </div>
              </div>
              <span
                className={`pillar-badge ${
                  geminiStatus === 'SUCCESS'
                    ? geminiAssessment === 'SUSPICIOUS'
                      ? 'match'
                      : geminiAssessment === 'NOT_OBVIOUSLY_SUSPICIOUS'
                      ? 'clean'
                      : 'warn'
                    : geminiStatus === 'SKIPPED'
                    ? 'dim'
                    : geminiStatus === 'UNAVAILABLE'
                    ? 'warn'
                    : 'dim'
                }`}
              >
                {geminiStatus === 'SUCCESS'
                  ? geminiAssessment.replace(/_/g, ' ')
                  : geminiStatus === 'SKIPPED'
                  ? 'Skipped (Quota)'
                  : geminiStatus === 'UNAVAILABLE'
                  ? 'Unavailable'
                  : 'Not Configured'}
              </span>
            </div>

            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '3px' }}>AI Assessment</div>
              <div
                className="pillar-metric"
                style={{
                  color:
                    geminiAssessment === 'SUSPICIOUS'
                      ? '#ff6b6b'
                      : geminiAssessment === 'NOT_OBVIOUSLY_SUSPICIOUS'
                      ? '#34d399'
                      : 'var(--text-muted)',
                }}
              >
                {geminiStatus === 'SUCCESS'
                  ? geminiAssessment
                  : geminiStatus === 'SKIPPED'
                  ? 'CONVINCING ML (SKIPPED)'
                  : 'UNCONFIGURED / DISABLED'}
              </div>
            </div>

            <div className="pillar-desc">
              {geminiAnalysis?.explanation ||
                'Optional secondary opinion invoked conditionally on borderline ML scores or structural evidence conflicts.'}
            </div>

            <div className="pillar-note">
              <strong>Role:</strong> Secondary qualitative analysis on sanitized tokens. Never treated as a verified blacklist match, calibrated probability, or proof of safety alone.
            </div>
          </div>
        </div>
      </div>

      {/* Explanation Section */}
      <div className="glass-panel result-section">
        <h3 className="section-heading">
          <Info size={20} style={{ color: 'var(--accent-blue)' }} />
          Analysis & Decision Rationale
        </h3>
        <p className="explanation-text">{explanation}</p>
      </div>

      {/* System Limitations & Disclosures */}
      {limitations && limitations.length > 0 && (
        <div className="limitations-box">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
            <FileText size={16} style={{ color: 'var(--accent-cyan)' }} />
            <span>Operational Limitations & Evidence Disclosures ({limitations.length})</span>
          </div>
          <ul className="limitations-list">
            {limitations.map((lim, idx) => (
              <li key={idx}>{lim}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Extracted Indicators Grid */}
      {indicators && indicators.length > 0 && (
        <div className="glass-panel result-section">
          <h3 className="section-heading">
            <Layers size={20} style={{ color: 'var(--accent-cyan)' }} />
            Observable Structural & Lexical Indicators ({indicators.length})
          </h3>
          <div className="indicators-grid">
            {indicators.map((indicator, index) => {
              const sev = (indicator.severity || 'INFO').toLowerCase();
              return (
                <div key={index} className="indicator-card">
                  <div className="indicator-header">
                    <span className="indicator-name">{indicator.name}</span>
                    <span className={`indicator-tag ${sev}`}>{indicator.severity}</span>
                  </div>
                  <div className="indicator-value">{indicator.value}</div>
                  <div className="indicator-desc">{indicator.description}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Recommended Precautions */}
      {precautions && precautions.length > 0 && (
        <div className="glass-panel result-section">
          <h3 className="section-heading">
            <ShieldCheck size={20} style={{ color: 'var(--color-legit)' }} />
            Recommended Defensive Precautions
          </h3>
          <ul className="precautions-list">
            {precautions.map((precaution, idx) => (
              <li key={idx} className="precaution-item">
                <CheckCircle size={18} className="precaution-icon" />
                <span>{precaution}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Bottom Actions */}
      <div className="result-actions">
        <button className="btn-secondary" onClick={onScanAgain}>
          <RefreshCw size={16} />
          <span>Scan Another URL</span>
        </button>
      </div>
    </div>
  );
}
