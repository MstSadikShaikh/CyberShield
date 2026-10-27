import React, { useState, useEffect } from 'react';
import {
  History,
  RefreshCw,
  Search,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  HelpCircle,
  Clock,
  Layers,
  Database,
  Eye,
} from 'lucide-react';
import { apiService } from '../services/api';

export function ScanHistory({ onSelectScan }) {
  const [historyList, setHistoryList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterText, setFilterText] = useState('');
  const [limit, setLimit] = useState(25);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getRecentScans(limit);
      setHistoryList(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || 'Failed to load scan history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [limit]);

  const handleRowClick = async (id) => {
    try {
      const fullScan = await apiService.getScanById(id);
      onSelectScan(fullScan);
    } catch (err) {
      alert('Unable to load scan details: ' + err.message);
    }
  };

  const filteredHistory = historyList.filter((item) => {
    if (!filterText) return true;
    const lower = filterText.toLowerCase();
    return (
      (item.submittedUrl && item.submittedUrl.toLowerCase().includes(lower)) ||
      (item.prediction && item.prediction.toLowerCase().includes(lower)) ||
      (item.riskLevel && item.riskLevel.toLowerCase().includes(lower))
    );
  });

  return (
    <div className="glass-panel history-card">
      <div className="history-header">
        <div>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <History size={24} style={{ color: 'var(--accent-blue)' }} />
            Public Threat Audit Log
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.35rem' }}>
            Persistent scan records stored in MySQL. Shared community audit trail (no accounts or logins required).
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            style={{
              background: 'rgba(7, 11, 19, 0.8)',
              color: 'var(--text-main)',
              border: '1px solid var(--border-subtle)',
              padding: '0.55rem 0.85rem',
              borderRadius: 'var(--radius-sm)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.85rem',
            }}
          >
            <option value={10}>Last 10 records</option>
            <option value={25}>Last 25 records</option>
            <option value={50}>Last 50 records</option>
            <option value={100}>Last 100 records</option>
          </select>

          <button className="btn-secondary" onClick={fetchHistory} disabled={loading}>
            <RefreshCw size={15} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div style={{ marginBottom: '1.25rem' }}>
        <div className="input-group">
          <Search className="input-icon" size={17} />
          <input
            type="text"
            className="url-input"
            style={{ padding: '0.75rem 1rem 0.75rem 2.8rem', fontSize: '0.9rem' }}
            placeholder="Filter audit log by domain, keywords, or prediction..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
          />
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          style={{
            padding: '1rem',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 'var(--radius-md)',
            color: '#f87171',
            marginBottom: '1rem',
            fontSize: '0.9rem',
          }}
        >
          {error}
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          <div
            style={{
              width: '32px',
              height: '32px',
              border: '3px solid rgba(0, 240, 255, 0.2)',
              borderTopColor: 'var(--accent-blue)',
              borderRadius: '50%',
              margin: '0 auto 1rem',
              animation: 'spin 0.8s linear infinite',
            }}
          />
          <p>Retrieving scan history from MySQL database...</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && filteredHistory.length === 0 && (
        <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          <Database size={40} style={{ color: 'var(--text-dim)', marginBottom: '0.75rem' }} />
          <h3>No audit records found</h3>
          <p style={{ marginTop: '0.35rem', fontSize: '0.9rem' }}>
            {filterText ? 'No records matched your filter criteria.' : 'Scan a URL to create the first record!'}
          </p>
        </div>
      )}

      {/* Table state */}
      {!loading && !error && filteredHistory.length > 0 && (
        <div className="history-table-wrapper">
          <table className="history-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Inspected URL</th>
                <th>Prediction</th>
                <th>Risk Score</th>
                <th>Classification</th>
                <th>Audit Timestamp</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.map((item) => {
                const isPhish = item.prediction === 'PHISHING';
                const isLegit = item.prediction === 'LEGITIMATE';
                const statusTag = isPhish ? 'phish' : isLegit ? 'legit' : 'uncertain';

                return (
                  <tr key={item.id} style={{ cursor: 'pointer' }} onClick={() => handleRowClick(item.id)}>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>#{item.id}</td>
                    <td>
                      <div className="history-url" title={item.submittedUrl}>
                        {item.submittedUrl}
                      </div>
                    </td>
                    <td>
                      <span className={`indicator-tag ${isPhish ? 'danger' : isLegit ? 'safe' : 'warning'}`}>
                        {item.prediction}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          color: isPhish ? '#ff6b6b' : isLegit ? '#34d399' : '#fbbf24',
                        }}
                      >
                        {Math.round(item.riskScore)} / 100
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{item.riskLevel}</td>
                    <td style={{ color: 'var(--text-dim)', fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>
                      {new Date(item.scannedAt).toLocaleString()}
                    </td>
                    <td>
                      <button
                        className="btn-secondary"
                        style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRowClick(item.id);
                        }}
                      >
                        <Eye size={13} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
