#!/bin/bash

# Variables
DOCKER_COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"

# Vérifier que le fichier .env existe
if [ ! -f "$ENV_FILE" ]; then
    echo "Le fichier $ENV_FILE n'existe pas. Création à partir du template..."
    cp .env.example .env
    echo "Veuillez éditer le fichier .env avec vos valeurs avant de continuer."
    exit 1
fi

# Charger les variables d'environnement
export $(grep -v '^#' .env | xargs)

# Construire et démarrer les conteneurs
echo "Démarrage des services avec Docker Compose..."
docker-compose -f $DOCKER_COMPOSE_FILE up -d

# Attendre que les services soient prêts
echo "Attente du démarrage des services..."
sleep 10

# Vérifier que l'API est accessible
echo "Vérification de l'API..."
curl -f http://localhost:8000/health || echo "L'API n'est pas encore prête, veuillez patienter..."

echo "Déploiement terminé. L'API est accessible sur http://localhost:8000"
echo "Documentation Swagger: http://localhost:8000/docs"