#!/bin/bash

echo "Starting PDF Annotator container..."
docker run -d \
    --name pdf-annotator \
    -p 3389:3389 \
    -v "$(pwd)/app.db:/app/app.db" \
    -v "$(pwd)/uploads:/app/uploads" \
    -v "$(pwd)/images:/app/images" \
    -e FLASK_APP=app.py \
    -e FLASK_ENV=production \
    --restart unless-stopped \
    pdf-annotator:latest

if [ $? -eq 0 ]; then
    echo "✓ Container started successfully!"
    echo "Application is running at http://localhost:3389"
    echo "View logs with: docker logs -f pdf-annotator"
    echo "Stop with: docker stop pdf-annotator"
    echo "Remove with: docker rm pdf-annotator"
else
    echo "✗ Failed to start container"
    exit 1
fi

