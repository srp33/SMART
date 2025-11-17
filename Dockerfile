# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for PyMuPDF
RUN apt-get update && apt-get install -y \
    libmupdf-dev \
    libfreetype6-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy and set up entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create necessary directories with proper permissions
# The app will create uploads/images on startup, but we ensure they exist
RUN mkdir -p uploads images

# Ensure the app directory is writable (for database creation)
# Note: When volumes are mounted, they override these permissions
# but this ensures the base structure is correct
RUN chmod 755 /app

# Expose port
EXPOSE 3389

# Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Set entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:3389", "--workers", "4", "--timeout", "120", "app:app"]
