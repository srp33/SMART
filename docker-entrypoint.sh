#!/bin/bash
# Entrypoint script to ensure database file exists and has proper permissions

# Check if app.db is a directory (Docker creates dir if file doesn't exist when mounting)
if [ -d /app/app.db ]; then
    echo "ERROR: app.db is mounted as a directory instead of a file!"
    echo "This happens when Docker mounts a file that doesn't exist on the host."
    echo "Please run: rm -rf ./app.db && touch ./app.db"
    echo "Then restart the container."
    exit 1
elif [ ! -f /app/app.db ]; then
    echo "Database file not found, creating..."
    touch /app/app.db
    chmod 666 /app/app.db
fi

# Ensure directories exist
mkdir -p /app/uploads /app/images
chmod 755 /app/uploads /app/images

# Execute the main command
exec "$@"

