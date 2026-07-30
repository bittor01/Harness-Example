# Use the official lightweight Python slim image to keep the image footprint as small as possible.
FROM python:3.11-slim

# Set the working directory inside the container.
WORKDIR /app

# Prevent Python from writing .pyc files to disc and enable unbuffered logging.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install standard curl for health checks or debugging, clean up package manager caches to keep layer small.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements file first to leverage Docker layer caching.
COPY requirements.txt .

# Install pinned dependencies cleanly and quickly.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files (dataset, app code, etc.) into the container.
COPY . .

# Create a global wrapper command alias 'prompt' that programmatically catches empty/help inputs
# and displays a friendly usage banner cleanly in shell before running Python.
RUN echo '#!/bin/sh\n\
if [ -z "$1" ] || [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then\n\
    echo "\\033[93m"\n\
    echo "============================================================="\n\
    echo "💡 QUICK USAGE TIP:"\n\
    echo "To query this MITRE Agent Harness, use our global '\''prompt'\'' command!"\n\
    echo ""\n\
    echo "👉 Syntax: prompt \\"<your cybersecurity query>\\""\n\
    echo "👉 Example: prompt \\"What are mitigations for T1078.001?\\""\n\
    echo "============================================================="\n\
    echo "\\033[0m"\n\
    exit 0\n\
fi\n\
python /app/app.py "$@"' > /usr/bin/prompt && \
    chmod +x /usr/bin/prompt

# Set a non-exiting CMD to keep the container running in the background.
# This prevents it from immediately trying to run a query or exiting on start,
# waiting cleanly for any 'docker exec' CLI or GUI command.
CMD ["tail", "-f", "/dev/null"]
