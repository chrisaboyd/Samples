FROM postgres:15

# Environment variables for PostgreSQL
ENV POSTGRES_DB=api_db
ENV POSTGRES_USER=api_user
ENV POSTGRES_PASSWORD=api_password

# Create directory for initialization scripts
RUN mkdir -p /docker-entrypoint-initdb.d

# Copy initialization scripts
COPY ./init.sql /docker-entrypoint-initdb.d/

# Expose PostgreSQL port
EXPOSE 5432

# Set the default command
CMD ["postgres"]
