import { useState } from 'react';
import { authFetch } from '../api.js';
import { relativeTime } from '../format.js';
import UsageChart from './UsageChart.jsx';

export default function KeyDetailPanel({ apiKey, usageData, onRevoke, onClose, showNotification }) {
  const [rotating, setRotating] = useState(false);
  const [newKey, setNewKey] = useState(null);
  const [revoking, setRevoking] = useState(false);

  const handleRotate = async () => {
    setRotating(true);
    try {
      const res = await authFetch(`/api/keys/${apiKey.id}/rotate`, { method: 'POST' });
      if (res.status === 429) {
        showNotification('Rate limited. Try again later.', 'warning');
      } else if (res.ok) {
        const data = await res.json();
        setNewKey(data.key);
        showNotification('Key rotated! Copy the new value now.', 'success');
      }
    } finally {
      setRotating(false);
    }
  };

  const handleRevoke = async () => {
    if (!confirm('Revoke this key? This cannot be undone.')) return;
    setRevoking(true);
    try {
      const res = await authFetch(`/api/keys/${apiKey.id}`, { method: 'DELETE' });
      if (res.ok) {
        showNotification('Key revoked.', 'info');
        onRevoke(apiKey.id);
        onClose();
      }
    } finally {
      setRevoking(false);
    }
  };

  const copy = (text) => {
    navigator.clipboard?.writeText(text);
    showNotification('Copied to clipboard!', 'success');
  };

  return (
    <div className="key-detail-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700 }}>{apiKey.name}</h3>
        <button className="btn btn-secondary btn-sm" onClick={onClose}>✕ Close</button>
      </div>

      <div className="detail-grid">
        <div className="detail-item">
          <label>Key Prefix</label>
          <p><span className="key-prefix">{apiKey.prefix}</span></p>
        </div>
        <div className="detail-item">
          <label>Environment</label>
          <p>{apiKey.environment}</p>
        </div>
        <div className="detail-item">
          <label>Status</label>
          <p><span className={`badge badge-${apiKey.status}`}>{apiKey.status}</span></p>
        </div>
        <div className="detail-item">
          <label>Rate Limit</label>
          <p>{apiKey.rateLimit?.toLocaleString()} req/hr</p>
        </div>
        <div className="detail-item">
          <label>Permissions</label>
          <p>{apiKey.permissions?.join(', ')}</p>
        </div>
        <div className="detail-item">
          <label>Last Used</label>
          <p>{relativeTime(apiKey.lastUsed)}</p>
        </div>
        <div className="detail-item">
          <label>Requests Today</label>
          <p>{apiKey.usage?.today?.toLocaleString()}</p>
        </div>
        <div className="detail-item">
          <label>This Month</label>
          <p>{apiKey.usage?.thisMonth?.toLocaleString()}</p>
        </div>
      </div>

      {newKey && (
        <div className="key-reveal">
          <div className="key-reveal-warn">⚠️ Copy this key now — it won't be shown again.</div>
          <div className="key-reveal-value">{newKey}</div>
          <button className="btn-copy" onClick={() => copy(newKey)}>Copy</button>
        </div>
      )}

      {apiKey.status !== 'revoked' && (
        <div className="detail-actions">
          <button className="btn btn-secondary btn-sm" onClick={handleRotate} disabled={rotating}>
            {rotating ? 'Rotating...' : '🔄 Rotate Key'}
          </button>
          <button className="btn btn-danger btn-sm" onClick={handleRevoke} disabled={revoking}>
            {revoking ? 'Revoking...' : '🗑️ Revoke Key'}
          </button>
        </div>
      )}

      <UsageChart data={usageData} keyStatus={apiKey.status} />
    </div>
  );
}
