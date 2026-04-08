# Base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy dependency dulu (biar cache optimal)
COPY requirements.txt .

# Install dependency
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src ./src
COPY models ./models

# Set PYTHONPATH supaya import clean
ENV PYTHONPATH=/app/src

# Expose gRPC port
EXPOSE 50051

# Run server
CMD ["python", "src/main.py"]