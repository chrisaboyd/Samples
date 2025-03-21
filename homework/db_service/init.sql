-- Create tables

-- Users table
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Messages table (with "hello world" string)
CREATE TABLE messages (
  id SERIAL PRIMARY KEY,
  content TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Items table
CREATE TABLE items (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  price NUMERIC(10, 2),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- User Table
INSERT INTO users (username, email) VALUES
  ('cboyd', 'cboyd@ps.com'),
  ('jdoe', 'jdoe@ps.com');

-- Messages Table
INSERT INTO messages (content) VALUES ('hello world');

-- Items Table
INSERT INTO items (name, description, price) VALUES
  ('Toilet Paper', '4-Ply, not John Wayne Wild West', 19.99),
  ('Dog Food', 'Purina, 100% Organic', 29.99),
  ('Headphone', 'Sony MDR-ZX110, Noise Cancelling', 39.99); 