-- Create Bifrost database (for Postgres mode)
CREATE DATABASE bifrost;
\c bifrost
CREATE USER bifrost WITH PASSWORD 'bifrost-password';
GRANT ALL PRIVILEGES ON DATABASE bifrost TO bifrost;