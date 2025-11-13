# gmail dockerfile
FROM python:3.12-slim

WORKDIR /app

LABEL app.id="3"
LABEL app.name="Gmail-Chatbot"
LABEL app.description="Chatbot local pour interactions Gmail"
LABEL app.details="Outil pour gérer des interactions avec Gmail (envoyé, écrire...), en utilisant Mistral pour les réponses."
LABEL app.created_date="2025-07-11"
LABEL app.app_url=""
LABEL app.docker_image="test-deploy-wedds/gmail:latest"
LABEL app.container_port="5000"
LABEL app.path="/"
LABEL app.tags="api, analytics, work"

RUN apt-get update && apt-get install -y     gcc     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app
USER app

EXPOSE 5000

ENV FLASK_APP=app.py
#ENV FLASK_ENV=production
ENV PYTHONPATH=/app
ENV PORT=5000

CMD ["python", "app.py"]
