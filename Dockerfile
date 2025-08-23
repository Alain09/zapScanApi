FROM python:3.9-slim-bullseye

WORKDIR /app

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    curl \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de requirements
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY zap_scanner.py .
COPY api_server.py .
COPY .env .

# Exposer le port
EXPOSE 8000

# Commande de démarrage
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]