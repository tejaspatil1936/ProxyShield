import { useState, useEffect } from 'react';
import { API } from '../api.js';
import Navbar from './Navbar.jsx';
import APIKeyList from './APIKeyList.jsx';
import KeyDetailPanel from './KeyDetailPanel.jsx';
import AttackPanel from './AttackPanel.jsx';

export default function Dashboard({ user, apiKeys, selectedKey, usageData, onSelectKey, onRefresh, onLogout, showNotification }) {
  const [activeTab, setActiveTab] = useState('keys');
  const [overview, setOverview] = useState(null);

  useEffect(() => {
    fetch(`${API}/api/usage/overview`)
      .then(r => r.json())
      .then(setOverview)
      .catch(() => {});
  }, [apiKeys]);

  const handleRevoke = (id) => {
    onRefresh();
  };

  const navLinks = [
    { id: 'keys', label: '🔑 API Keys' },
    { id: 'usage', label: '📊 Usage Overview' },
    { id: 'settings', label: '⚙️ Settings' },
  ];

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-logo">🔑 KeyVault</div>
        <div className="sidebar-tagline">Protected by ProxyShield</div>
        <nav className="sidebar-nav">
          {navLinks.map(link => (
            <button
              key={link.id}
              className={`sidebar-link ${activeTab === link.id ? 'active' : ''}`}
              onClick={() => setActiveTab(link.id)}
            >
              {link.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          {user && (
            <div className="user-info">
              <div className="user-name">{user.name}</div>
              <div className="user-role">{user.role}</div>
            </div>
          )}
          <button className="btn-logout" onClick={onLogout}>Sign out</button>
        </div>
      </div>

      {/* Main */}
      <div className="main-content">
        <Navbar user={user} onLogout={onLogout} />
        <div className="page-content">
          {/* Stats row */}
          {overview && (
            <div className="stats-row">
              <div className="stat-card">
                <div className="stat-label">Total Keys</div>
                <div className="stat-value">{overview.totalKeys}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Active Keys</div>
                <div className="stat-value">{overview.activeKeys}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Requests Today</div>
                <div className="stat-value">{overview.totalRequestsToday?.toLocaleString()}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">This Month</div>
                <div className="stat-value">{overview.totalRequestsMonth?.toLocaleString()}</div>
              </div>
            </div>
          )}

          {activeTab === 'keys' && (
            <>
              <APIKeyList
                apiKeys={apiKeys}
                onSelectKey={onSelectKey}
                onRefresh={onRefresh}
                showNotification={showNotification}
              />
              {selectedKey && (
                <KeyDetailPanel
                  apiKey={selectedKey}
                  usageData={usageData}
                  onRevoke={handleRevoke}
                  onClose={() => onSelectKey(null)}
                  showNotification={showNotification}
                />
              )}
            </>
          )}

          {activeTab === 'usage' && (
            <div className="card">
              <div className="section-title" style={{ marginBottom: 16 }}>Usage Overview</div>
              <p style={{ color: 'var(--muted)' }}>Select a key from the API Keys tab to see detailed usage charts.</p>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="card">
              <div className="section-title" style={{ marginBottom: 16 }}>Settings</div>
              <p style={{ color: 'var(--muted)' }}>Coming soon.</p>
            </div>
          )}
        </div>
      </div>

      <AttackPanel showNotification={showNotification} />
    </div>
  );
}
