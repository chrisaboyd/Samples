import React from 'react';
import './App.css';

function App() {
  const handleClick = () => {
    alert('Error: Feature not implemented');
  };

  return (
    <div className="App">
      <button className="center-button" onClick={handleClick}>
        Who am I?
      </button>
    </div>
  );
}

export default App;