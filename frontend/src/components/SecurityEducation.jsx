import React from 'react';
import {
  BookOpen,
  Lock,
  KeyRound,
  AlertOctagon,
  CheckCircle2,
  ExternalLink,
  ShieldAlert,
  Globe,
  FileQuestion,
  Fingerprint,
} from 'lucide-react';

export function SecurityEducation() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Education Header */}
      <div className="glass-panel" style={{ padding: '2.2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
          <BookOpen size={28} style={{ color: 'var(--accent-blue)' }} />
          <h2>Security Awareness & Phishing Defense Hub</h2>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '1.05rem', lineHeight: '1.6' }}>
          Phishing remains the #1 initial attack vector in cyber breaches worldwide. Learn how modern attackers craft
          deceptive URLs and how you can protect your digital identity using defensive best practices.
        </p>
      </div>

      {/* Grid of Educational Topics */}
      <div className="edu-grid">
        {/* Card 1: The HTTPS Myth */}
        <div className="glass-panel edu-card" style={{ borderColor: 'rgba(239, 68, 68, 0.25)' }}>
          <h3 style={{ color: '#ff7b7b' }}>
            <Lock size={22} />
            The HTTPS / Padlock Myth
          </h3>
          <p>
            <strong>HTTPS does NOT mean a website is legitimate or safe.</strong>
          </p>
          <p>
            HTTPS only proves that the data transmitted between your browser and the web server is encrypted in transit.
            Today, automated certificate authorities (such as Let's Encrypt and Cloudflare) provide free SSL certificates in seconds.
          </p>
          <p>
            Industry threat intelligence reports indicate that <strong>over 80% of active phishing websites</strong> now use valid
            HTTPS certificates and display the browser padlock icon. Never assume safety solely from "https://".
          </p>
        </div>

        {/* Card 2: Anatomy of Deceptive URLs */}
        <div className="glass-panel edu-card">
          <h3 style={{ color: 'var(--accent-blue)' }}>
            <Globe size={22} />
            URL Anatomy & Impersonation
          </h3>
          <p>
            Attackers exploit cognitive blindspots by crafting addresses that superficially resemble reputable organizations:
          </p>
          <ul className="checklist">
            <li>
              <AlertOctagon size={16} style={{ color: 'var(--color-uncertain)', flexShrink: 0 }} />
              <span>
                <strong>Subdomain Padding:</strong> <code>paypal.com.verify-account.tk</code> is hosted on <em>verify-account.tk</em>, NOT paypal.com.
              </span>
            </li>
            <li>
              <AlertOctagon size={16} style={{ color: 'var(--color-uncertain)', flexShrink: 0 }} />
              <span>
                <strong>Hyphenated Domains:</strong> <code>microsoft-security-auth.com</code> is an unaffiliated third-party domain.
              </span>
            </li>
            <li>
              <AlertOctagon size={16} style={{ color: 'var(--color-uncertain)', flexShrink: 0 }} />
              <span>
                <strong>Homoglyph Attacks:</strong> Replacing ASCII 'o' with Cyrillic 'о' or 'l' with '1' to deceive the human eye.
              </span>
            </li>
            <li>
              <AlertOctagon size={16} style={{ color: 'var(--color-uncertain)', flexShrink: 0 }} />
              <span>
                <strong>UserInfo '@' Spoofing:</strong> <code>google.com@evil-site.com</code> navigates to <em>evil-site.com</em>.
              </span>
            </li>
          </ul>
        </div>

        {/* Card 3: Recognizing Fake Login Pages */}
        <div className="glass-panel edu-card">
          <h3 style={{ color: 'var(--accent-cyan)' }}>
            <FileQuestion size={22} />
            Spotting Fake Login Portals
          </h3>
          <p>
            Credential harvesting is designed to replicate legitimate portals (Google Workspace, Microsoft 365, banks, social media).
          </p>
          <ul className="checklist">
            <li>
              <CheckCircle2 size={16} style={{ color: 'var(--accent-blue)', flexShrink: 0 }} />
              <span><strong>Check the browser address bar:</strong> Verify the root domain matches the authentic brand.</span>
            </li>
            <li>
              <CheckCircle2 size={16} style={{ color: 'var(--accent-blue)', flexShrink: 0 }} />
              <span><strong>Watch for artificial urgency:</strong> Messages threatening account suspension within 24 hours.</span>
            </li>
            <li>
              <CheckCircle2 size={16} style={{ color: 'var(--accent-blue)', flexShrink: 0 }} />
              <span><strong>Password manager litmus test:</strong> Bitwarden or 1Password won't autofill on lookalike domains.</span>
            </li>
          </ul>
        </div>

        {/* Card 4: Essential Defense Checklist */}
        <div className="glass-panel edu-card">
          <h3 style={{ color: 'var(--color-legit)' }}>
            <KeyRound size={22} />
            Essential Defense Checklist
          </h3>
          <p>Adopt these fundamental cybersecurity habits to minimize your attack surface:</p>
          <ul className="checklist">
            <li>
              <Fingerprint size={16} style={{ color: 'var(--color-legit)', flexShrink: 0 }} />
              <span><strong>Enable Multi-Factor Authentication (MFA):</strong> Use authenticator apps or hardware keys (FIDO2 / YubiKey). Avoid SMS where possible.</span>
            </li>
            <li>
              <CheckCircle2 size={16} style={{ color: 'var(--color-legit)', flexShrink: 0 }} />
              <span><strong>Never copy-paste sensitive credentials:</strong> If in doubt, open a fresh browser tab and manually enter the official bookmark.</span>
            </li>
            <li>
              <CheckCircle2 size={16} style={{ color: 'var(--color-legit)', flexShrink: 0 }} />
              <span><strong>Report Suspicious Messages:</strong> Forward phishing emails to <code>reportphishing@apwg.org</code> or your organization's IT department.</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
