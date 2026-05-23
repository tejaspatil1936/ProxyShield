import { useState } from 'react';

export default function LoginPage({ onLogin }) {
  const [email, setEmail] = useState('admin@apikeys.dev');
  const [password, setPassword] = useState('admin123');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await onLogin(email, password);
    setLoading(false);
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">🔑 KeyVault</div>
        <div className="login-subtitle">Manage, monitor, and secure your API keys</div>

        <div style={{
          margin: '12px 0 4px', padding: '8px 12px', borderRadius: 8,
          background: 'rgba(124, 45, 18, 0.12)', border: '1px solid rgba(124, 45, 18, 0.35)',
          color: '#9a3412', fontSize: 12, lineHeight: 1.4, textAlign: 'center'
        }}>
          ⚠️ <strong>Demo app</strong> — data is in-memory (resets on restart) and the
          login below is a shared sample credential. Do not deploy as-is; it exists to
          showcase ProxyShield protecting a backend.
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              type="email"
              className="form-input"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="admin@apikeys.dev"
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              className="form-input"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>
          <button type="submit" className="btn-login" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <div style={{ marginTop: 16, fontSize: 12, color: 'var(--muted)', textAlign: 'center' }}>
          Credentials: admin@apikeys.dev / admin123
        </div>
      </div>
    </div>
  );
}
