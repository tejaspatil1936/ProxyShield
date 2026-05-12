import { useState } from 'react';
import { API } from '../api.js';

export default function AttackPanel({ showNotification }) {
  const [open, setOpen] = useState(false);
  const [results, setResults] = useState({});
  const [loading, setLoading] = useState({});

  const setResult = (key, msg, type) => setResults(r => ({ ...r, [key]: { msg, type } }));
  const setLoad = (key, v) => setLoading(l => ({ ...l, [key]: v }));

  const bruteForce = async () => {
    setLoad('brute', true);
    setResult('brute', 'Running 10 attempts...', '');
    let blocked = 0;
    for (let i = 0; i < 10; i++) {
      try {
        const res = await fetch(`${API}/api/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'hack@test.com', password: `wrong${i}` })
        });
        if (res.status === 429) blocked++;
      } catch (_) {}
    }
    setResult('brute', `${blocked}/10 blocked by rate limiter`, blocked > 0 ? 'blocked' : 'success');
    setLoad('brute', false);
    if (blocked > 0) showNotification(`Brute force blocked: ${blocked}/10 attempts stopped`, 'error');
  };

  const sqlInjection = async () => {
    setLoad('sql', true);
    try {
      const res = await fetch(`${API}/api/keys/search?q=' UNION SELECT * FROM secrets --`);
      if (res.status === 403) setResult('sql', 'SQL injection blocked ✓', 'blocked');
      else setResult('sql', `Passed through (status ${res.status})`, 'success');
    } catch (_) {
      setResult('sql', 'Request failed', '');
    }
    setLoad('sql', false);
  };

  const xssAttack = async () => {
    setLoad('xss', true);
    try {
      const res = await fetch(`${API}/api/keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: '<script>steal(document.cookie)</script>' })
      });
      if (res.status === 403) setResult('xss', 'XSS blocked ✓', 'blocked');
      else setResult('xss', `Passed through (status ${res.status})`, 'success');
    } catch (_) {
      setResult('xss', 'Request failed', '');
    }
    setLoad('xss', false);
  };

  const honeypotProbe = async () => {
    setLoad('honey', true);
    try {
      const res = await fetch(`${API}/admin`);
      if (res.status === 403) setResult('honey', 'Honeypot triggered — IP banned ✓', 'blocked');
      else setResult('honey', `Not blocked (status ${res.status})`, 'success');
    } catch (_) {
      setResult('honey', 'Request failed', '');
    }
    setLoad('honey', false);
  };

  const entropyAttack = async () => {
    setLoad('entropy', true);
    // Build a payload with maximum character diversity → Shannon entropy ≈ 6.5 bits/byte,
    // well above the 5.5 threshold. Uses /api/scan which has NO rate limit so the WAF
    // entropy check always runs first (avoids the 429 bug from exhausted POST /api/keys bucket).
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?`~';
    const payload = Array.from({ length: 800 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    try {
      const res = await fetch(`${API}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: payload })
      });
      if (res.status === 403)      setResult('entropy', 'High entropy anomaly blocked ✓', 'blocked');
      else if (res.status === 429) setResult('entropy', 'Rate limited — bucket exhausted, try again in 60s', 'blocked');
      else                         setResult('entropy', `Not blocked — WAF passed it (${res.status})`, 'success');
    } catch (_) {
      setResult('entropy', 'Request failed', '');
    }
    setLoad('entropy', false);
  };

  const spamKeyCreation = async () => {
    setLoad('spam', true);
    setResult('spam', 'Firing 5 rapid requests...', '');
    let passed = 0, blocked = 0;
    await Promise.all(Array.from({ length: 5 }, async (_, i) => {
      try {
        const res = await fetch(`${API}/api/keys`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: `Spam Key ${i}` })
        });
        if (res.status === 429) blocked++;
        else passed++;
      } catch (_) {}
    }));
    setResult('spam', `${passed} passed, ${blocked} rate limited`, blocked > 0 ? 'blocked' : 'success');
    setLoad('spam', false);
  };

  const checkHeaders = async () => {
    setLoad('headers', true);
    try {
      const res = await fetch(`${API}/api/keys`);
      const remaining = res.headers.get('X-RateLimit-Remaining');
      const limit = res.headers.get('X-RateLimit-Limit');
      if (remaining !== null) {
        setResult('headers', `X-RateLimit-Remaining: ${remaining}/${limit}`, 'success');
      } else {
        setResult('headers', 'No rate limit headers found', '');
      }
    } catch (_) {
      setResult('headers', 'Request failed', '');
    }
    setLoad('headers', false);
  };

  const attacks = [
    { key: 'brute', label: '🔓 Brute Force Login', cls: 'attack-btn-red', fn: bruteForce },
    { key: 'sql', label: '💉 SQL Injection', cls: 'attack-btn-orange', fn: sqlInjection },
    { key: 'xss', label: '⚡ XSS in Key Name', cls: 'attack-btn-purple', fn: xssAttack },
    { key: 'honey', label: '🍯 Probe /admin', cls: 'attack-btn-yellow', fn: honeypotProbe },
    { key: 'entropy', label: '🔥 Encoded Attack', cls: 'attack-btn-pink', fn: entropyAttack },
    { key: 'spam', label: '🔄 Spam Key Creation', cls: 'attack-btn-teal', fn: spamKeyCreation },
    { key: 'headers', label: '📊 Check Headers', cls: 'attack-btn-blue', fn: checkHeaders },
  ];

  if (!open) {
    return (
      <button className="attack-panel-toggle" onClick={() => setOpen(true)}>
        🛡️ Attack Tester
      </button>
    );
  }

  return (
    <div className="attack-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="attack-panel-title">🛡️ ProxyShield Tester</div>
          <div className="attack-panel-sub">Test API security live</div>
        </div>
        <button
          style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: 16 }}
          onClick={() => setOpen(false)}
        >✕</button>
      </div>

      {attacks.map(({ key, label, cls, fn }) => (
        <div key={key}>
          <button
            className={`attack-btn ${cls}`}
            onClick={fn}
            disabled={loading[key]}
          >
            {loading[key] ? 'Running...' : label}
          </button>
          {results[key] && (
            <div className={`attack-result ${results[key].type}`}>
              {results[key].msg}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
