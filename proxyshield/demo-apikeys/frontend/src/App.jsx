import { useState, useEffect } from 'react';
import { API } from './api.js';
import LoginPage from './components/LoginPage.jsx';
import Dashboard from './components/Dashboard.jsx';
import Notification from './components/Notification.jsx';

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  const [notification, setNotification] = useState(null);
  const [apiKeys, setApiKeys] = useState([]);
  const [selectedKey, setSelectedKey] = useState(null);
  const [usageData, setUsageData] = useState(null);

  const showNotification = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 5000);
  };

  const login = async (email, password) => {
    const res = await fetch(`${API}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    if (res.status === 429) {
      showNotification('Too many attempts. Account locked.', 'warning');
      return false;
    }
    if (res.status === 403) {
      showNotification('Blocked by security system.', 'error');
      return false;
    }
    if (!res.ok) {
      showNotification('Invalid credentials.', 'error');
      return false;
    }
    const data = await res.json();
    setUser(data.user);
    setIsLoggedIn(true);
    return true;
  };

  const logout = () => {
    setIsLoggedIn(false);
    setUser(null);
    setApiKeys([]);
    setSelectedKey(null);
  };

  const fetchKeys = async () => {
    try {
      const res = await fetch(`${API}/api/keys`);
      if (res.ok) {
        setApiKeys(await res.json());
      }
    } catch (_) {}
  };

  useEffect(() => {
    if (isLoggedIn) fetchKeys();
  }, [isLoggedIn]);

  return (
    <div>
      {notification && (
        <Notification
          message={notification.msg}
          type={notification.type}
          onClose={() => setNotification(null)}
        />
      )}
      {isLoggedIn ? (
        <Dashboard
          user={user}
          apiKeys={apiKeys}
          selectedKey={selectedKey}
          usageData={usageData}
          onSelectKey={async (key) => {
            setSelectedKey(key);
            if (key) {
              try {
                const res = await fetch(`${API}/api/keys/${key.id}/usage`);
                if (res.ok) setUsageData(await res.json());
              } catch (_) {}
            } else {
              setUsageData(null);
            }
          }}
          onRefresh={fetchKeys}
          onLogout={logout}
          showNotification={showNotification}
        />
      ) : (
        <LoginPage onLogin={login} />
      )}
    </div>
  );
}
