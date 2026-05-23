import { useState } from 'react';
import { authFetch } from '../api.js';

export default function CreateKeyModal({ onClose, onCreate, showNotification }) {
  const [name, setName] = useState('');
  const [environment, setEnvironment] = useState('development');
  const [permissions, setPermissions] = useState(['read']);
  const [rateLimit, setRateLimit] = useState(1000);
  const [loading, setLoading] = useState(false);
  const [newKey, setNewKey] = useState(null);

  const togglePerm = (p) => {
    setPermissions(prev =>
      prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p]
    );
  };

  const copy = (text) => {
    navigator.clipboard?.writeText(text);
    showNotification('Copied to clipboard!', 'success');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await authFetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, permissions, environment, rateLimit: Number(rateLimit) })
      });
      if (res.status === 429) {
        showNotification('Rate limit exceeded on key creation.', 'warning');
        return;
      }
      if (res.status === 403) {
        showNotification('Request blocked by ProxyShield.', 'error');
        return;
      }
      if (res.ok) {
        const data = await res.json();
        setNewKey(data.key);
        onCreate(data);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-title">Create New API Key</div>

        {newKey ? (
          <div>
            <p style={{ marginBottom: 12, color: 'var(--text-light)' }}>Your new API key has been created.</p>
            <div className="key-reveal">
              <div className="key-reveal-warn">⚠️ This key will only be shown once. Copy it now.</div>
              <div className="key-reveal-value">{newKey}</div>
              <button className="btn-copy" onClick={() => copy(newKey)}>Copy Key</button>
            </div>
            <div className="modal-footer">
              <button className="btn btn-primary" onClick={onClose}>Done</button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Key Name</label>
              <input className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Production API" required />
            </div>
            <div className="form-group">
              <label className="form-label">Environment</label>
              <select className="form-input" value={environment} onChange={e => setEnvironment(e.target.value)}>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Permissions</label>
              <div className="checkbox-group">
                {['read', 'write', 'admin'].map(p => (
                  <label key={p} className="checkbox-label">
                    <input type="checkbox" checked={permissions.includes(p)} onChange={() => togglePerm(p)} />
                    {p}
                  </label>
                ))}
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Rate Limit (req/hr)</label>
              <input type="number" className="form-input" value={rateLimit} onChange={e => setRateLimit(e.target.value)} min="1" />
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Create Key'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
