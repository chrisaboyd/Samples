import React, { useState } from 'react';
import './App.css';

// Mock user database
const USERS = [
  { id: 1, email: 'alice@example.com', password: 'alice123', name: 'Alice' },
  { id: 2, email: 'bob@example.com', password: 'bob456', name: 'Bob' },
  { id: 3, email: 'admin@example.com', password: 'admin789', name: 'Admin' },
];

function App() {
  const [user, setUser] = useState(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    
    // Find user by email
    const found = USERS.find(u => u.email === email);
    
    // Intentional vulnerability: checks if password matches OR if user exists
    // This allows bypassing password check by just providing a valid email
    if (found && (found.password === password || found)) {
      setUser(found);
    } else {
      alert('Invalid credentials');
    }
  };

  const handleWhoAmI = () => {
    if (user) {
      alert(`You are logged in as: ${user.name}`);
    } else {
      alert('Error: Please log in first');
    }
  };

  const handleLogout = () => {
    setUser(null);
    setEmail('');
    setPassword('');
  };

  if (!user) {
    return (
      <div className="App">
        <form className="login-form" onSubmit={handleLogin}>
          <h2>Login</h2>
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button type="submit">Log In</button>
        </form>
      </div>
    );
  }

  return (
    <div className="App">
      <button className="center-button" onClick={handleWhoAmI}>
        Who am I?
      </button>
      <button className="logout-button" onClick={handleLogout}>
        Logout
      </button>
    </div>
  );
}

export default App;