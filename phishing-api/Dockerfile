# Use Python 3.11 slim as base (stable, well-supported for torch)
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Pre-download email phishing and translation models
RUN python -c "\
from transformers import AutoTokenizer, AutoModelForSequenceClassification, MarianTokenizer, MarianMTModel; \
AutoTokenizer.from_pretrained('cybersectony/phishing-email-detection-distilbert_v2.4.1'); \
AutoModelForSequenceClassification.from_pretrained('cybersectony/phishing-email-detection-distilbert_v2.4.1'); \
MarianTokenizer.from_pretrained('Helsinki-NLP/opus-mt-tc-big-pt-en'); \
MarianMTModel.from_pretrained('Helsinki-NLP/opus-mt-tc-big-pt-en')"

# Copy application code
COPY app.py .
COPY server_features.py .

# Expose API port
EXPOSE 8000

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV MODEL_PATH=/app/model

# Health check using curl (no extra Python deps needed)
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
