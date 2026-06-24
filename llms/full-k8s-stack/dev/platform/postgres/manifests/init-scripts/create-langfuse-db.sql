-- Create Langfuse database
CREATE DATABASE langfuse;
\c langfuse
CREATE USER langfuse WITH PASSWORD 'langfuse-password';
GRANT ALL PRIVILEGES ON DATABASE langfuse TO langfuse;