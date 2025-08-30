# Scanner de Sécurité OWASP ZAP Automatisé

Un outil d'automatisation conteneurisé pour effectuer des scans de sécurité avec OWASP ZAP, incluant l'authentification par formulaire et une API REST pour l'intégration CI/CD.

![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![OWASP ZAP](https://img.shields.io/badge/OWASP_ZAP-00549E?style=flat&logo=owasp&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)

## 🔧 Fonctionnalités

- **🐳 Conteneurisation complète** : Déploiement Docker avec docker-compose
- **🕷️ Scan automatisé complet** : Spider classique et AJAX + Scan actif avec authentification
- **🔐 Gestion de l'authentification** : Support des formulaires de connexion
- **🚀 API REST** : Interface FastAPI pour déclencher des scans à distance
- **⚙️ Configuration flexible** : Fichier `.env` pour la gestion sécurisée des paramètres
- **📊 Rapports multiples** : Génération de rapports HTML et JSON
- **🔒 Gestion SSL** : Support des certificats auto-signés
- **📚 Documentation interactive** : Interface Swagger/OpenAPI automatique
- **🔄 Intégration CI/CD** : API REST pour pipelines d'automatisation

## 📁 Structure du Projet

```
zap-scanner/
├── 📄 .env.example               # Template de configuration
├── 🔒 .env                       # Configuration (ne pas commiter)
├── 🚫 .gitignore                # Fichiers à ignorer par Git
├── 🐳 Dockerfile               # Image Docker pour l'API
├── 🐙 docker-compose.yml       # Orchestration des services
├── 🐍 zap_scanner.py           # Script principal de scan
├── 🌐 api_server.py            # API REST FastAPI
├── 📦 requirements.txt         # Dépendances Python
├── 📁 zap_reports/             # Dossier des rapports générés
└── 📖 README.md               # Ce fichier
```

## 🚀 Installation et Déploiement

### Prérequis

- **Docker** 20.10+ et **Docker Compose** v2
- **Ports disponibles** : 8080 (ZAP), 8093 (API)
- **Serveur distant** avec accès SSH (optionnel)

### 1. Préparation de l'Environnement

```bash
# Cloner ou télécharger le projet
git clone <votre-repo> zap-scanner
cd zap-scanner

# Créer le fichier de configuration
cp .env.example .env
```

### 2. Configuration (.env)

Éditez le fichier `.env` avec vos paramètres :

```env
# === Configuration OWASP ZAP ===
ZAP_PROXY_URL=http://zap:8080
ZAP_API_KEY="votre-clé-api-zap-ici"

# === Configuration Application de Test ===
TARGET_URL=https://votre-application.com
LOGIN_URL=https://votre-application.com/login
TEST_USERNAME=utilisateur_test
TEST_PASSWORD=mot_de_passe_test
USERNAME_PARAM=username
PASSWORD_PARAM=password

# === Configuration API ===
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=info

# === Configuration Rapports ===
REPORTS_DIR=zap_reports
MAX_REPORTS_RETENTION=30
```

### 3. Déploiement avec Docker Compose

#### Démarrage des Services

```bash
# Construire et démarrer tous les services
docker-compose up -d --build

# Vérifier que les services sont actifs
docker-compose ps

# Suivre les logs en temps réel
docker-compose logs -f

# Logs d'un service spécifique
docker-compose logs -f zap-api
docker-compose logs -f zap
```

#### Vérification du Déploiement

```bash
# Vérifier la santé de l'API
curl http://localhost:8093/health

# Vérifier que ZAP fonctionne
curl http://localhost:8080/JSON/core/view/version/
```

### 4. Accès aux Services

- **API FastAPI** : `http://localhost:8093` (ou `http://votre-serveur:8093`)
- **Documentation Swagger** : `http://localhost:8093/docs`
- **OWASP ZAP Proxy** : `http://localhost:8080`

## ⚙️ Configuration Avancée

### Génération de la Clé API ZAP

La clé API ZAP est désactivée dans la configuration Docker pour simplifier l'usage. Si vous souhaitez l'activer :

1. **Modifier le docker-compose.yml** :
```yaml
# Remplacer dans la commande ZAP :
-config api.disablekey=true
# Par :
-config api.key=votre-cle-api-securisee
```

2. **Générer une clé API** :
```bash
# Générer une clé aléatoirement
openssl rand -base64 32

# Ou utiliser l'API ZAP une fois démarré
curl http://localhost:8080/JSON/core/action/generateApiKey/
```

### Personnalisation des Ports

Si les ports par défaut sont occupés, modifiez le `docker-compose.yml` :

```yaml
services:
  zap-api:
    ports:
      - "8094:8000"  # Changer le port externe
  zap:
    ports:
      - "8081:8080"  # Changer le port ZAP externe
```

## 🎯 Utilisation

### Mode Local avec ZAP Installé

Si vous avez OWASP ZAP installé localement sur votre PC :

```bash
# 1. Démarrer ZAP en mode daemon
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# 2. Configurer le .env pour pointer vers ZAP local
ZAP_PROXY_URL=http://127.0.0.1:8080

# 3. Exécuter le scanner directement
python zap_scanner.py

# 4. Ou démarrer seulement l'API FastAPI
python api_server.py
```

### Mode API REST (Recommandé)

#### 1. Vérifier la Configuration

```bash
# Voir la configuration actuelle
curl http://localhost:8093/config

# Vérifier l'état de santé
curl http://localhost:8093/health
```

#### 2. Lancer un Scan Rapide

```bash
# Scan avec les paramètres du fichier .env
curl -X POST "http://localhost:8093/quick-scan" \
     -H "Content-Type: application/json" \
     -d "{}"
```

#### 3. Lancer un Scan Personnalisé

```bash
curl -X POST "http://localhost:8093/scan" \
     -H "Content-Type: application/json" \
     -d '{
       "target_url": "https://example.com",
       "login_url": "https://example.com/login",
       "username": "testuser",
       "password": "testpass",
       "username_param": "email",
       "password_param": "password"
     }'
```

#### 4. Suivre un Scan en Cours

```bash
# Lister tous les scans
curl http://localhost:8093/scans

# Suivre un scan spécifique
curl http://localhost:8093/scan/{scan_id}
```

#### 5. Récupérer les Rapports

```bash
# Lister tous les rapports disponibles
curl http://localhost:8093/reports

# Télécharger le rapport HTML le plus récent
curl -O http://localhost:8093/reports/{report_id}/html

# Récupérer le rapport JSON
curl http://localhost:8093/reports/{report_id}/json
```

### Mode Script Direct (dans le conteneur)

```bash
# Exécuter le scanner directement
docker-compose exec zap-api python zap_scanner.py

# Ou avec des paramètres personnalisés
docker-compose exec zap-api python -c "
from zap_scanner import ZAPAutomatedScanner
scanner = ZAPAutomatedScanner('http://zap:8080')
scanner.target_url = 'https://votre-app.com'
scanner.run_full_scan()
"
```

## 📊 Endpoints API Disponibles

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/docs` | 📚 Documentation Swagger interactive |
| `GET` | `/health` | 🏥 État de santé de l'API |
| `GET` | `/config` | ⚙️ Configuration actuelle (sans secrets) |
| `POST` | `/scan` | 🔍 Démarrer un scan personnalisé |
| `GET` | `/scan/{scan_id}` | 📈 Statut d'un scan spécifique |
| `GET` | `/scans` | 📋 Liste de tous les scans |
| `GET` | `/reports` | 📄 Liste de tous les rapports |
| `GET` | `/reports/{report_id}/html` | ⬇️ Télécharger rapport HTML |
| `GET` | `/reports/{report_id}/json` | 📊 Récupérer rapport JSON |

## 🐳 Gestion Docker

### Commandes Utiles

```bash
# === GESTION DES SERVICES ===

# Démarrer les services
docker-compose up -d

# Arrêter les services
docker-compose down

# Redémarrer un service spécifique
docker-compose restart zap-api

# Reconstruire et redémarrer
docker-compose up -d --build --force-recreate

# === SURVEILLANCE ===

# Voir les logs en temps réel
docker-compose logs -f --tail=50

# Logs d'un service spécifique
docker-compose logs -f zap-api
docker-compose logs -f zap

# Statut des conteneurs
docker-compose ps

# Utilisation des ressources
docker stats

# === MAINTENANCE ===

# Entrer dans le conteneur de l'API
docker-compose exec zap-api bash

# Entrer dans le conteneur ZAP
docker-compose exec zap bash

# Voir les volumes
docker volume ls

# Nettoyer les ressources inutilisées
docker system prune -f

# Supprimer les images sans nom (dangling)
docker image prune -f

# Supprimer toutes les images inutilisées
docker image prune -a -f

# === SAUVEGARDE ET RESTAURATION ===

# Copier les rapports depuis le conteneur
docker cp $(docker-compose ps -q zap-api):/app/zap_reports ./backup_reports

# Sauvegarder les volumes
docker run --rm -v zap-scanner_zap_data:/data -v $(pwd):/backup alpine tar czf /backup/zap_data_backup.tar.gz -C /data .
```

### Monitoring et Debug

```bash
# Voir les processus dans les conteneurs
docker-compose exec zap-api ps aux
docker-compose exec zap ps aux

# Tester la connectivité entre services
docker-compose exec zap-api curl http://zap:8080/JSON/core/view/version/

# Vérifier les variables d'environnement
docker-compose exec zap-api env | grep ZAP

# Inspecter la configuration réseau
docker network inspect zap-scanner_default
```

## 📄 Format des Rapports

### Rapport JSON
```json
{
  "metadata": {
    "report_id": "scan_20240115_143022",
    "filename": "zap_report_20240115_143022.json",
    "file_size": 15234,
    "created_at": "2024-01-15T14:30:22"
  },
  "report": {
    "alerts": [
      {
        "name": "SQL Injection",
        "risk": "High",
        "confidence": "Medium",
        "url": "https://example.com/vulnerable",
        "description": "Description détaillée...",
        "solution": "Solution recommandée..."
      }
    ]
  }
}
```

## 🚀 Utilisation sur Serveur Distant

## 🚀 Utilisation sur Serveur Distant

### Méthodes de Transfert des Fichiers

#### Option 1: Transfert Direct (SCP/RSYNC)
```bash
# Via SCP
scp -r zap-scanner/ user@votre-serveur.com:~/

# Via RSYNC (plus efficace pour les mises à jour)
rsync -avz --exclude='.env' --exclude='zap_reports/' \
      zap-scanner/ user@votre-serveur.com:~/zap-scanner/
```

#### Option 2: Via GitHub
```bash
# Sur le serveur distant
git clone https://github.com/votre-utilisateur/zap-scanner.git
cd zap-scanner

# Pour les mises à jour
git pull origin main
```

#### Option 3: Via GitLab
```bash
# Sur le serveur distant
git clone https://gitlab.com/votre-utilisateur/zap-scanner.git
cd zap-scanner

# Configurer l'authentification si repo privé
git config credential.helper store
```

### Déploiement sur Serveur

```bash
# Se connecter au serveur distant
ssh user@votre-serveur.com

# Aller dans le répertoire du projet
cd ~/zap-scanner

# Configurer l'environnement
cp .env.example .env
# Éditer .env avec vos paramètres

# Démarrer les services
docker-compose up -d --build

# Vérifier que l'API est accessible
# Note: Remplacer 8093 par le port exposé configuré dans docker-compose.yml si modifié
curl http://votre-serveur.com:8093/health
```

### Configuration Firewall

```bash
# Ubuntu/Debian - Ouvrir les ports nécessaires
sudo ufw allow 8093/tcp  # API FastAPI
sudo ufw allow 8080/tcp  # ZAP (si accès direct requis)

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8093/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

### Utilisation Distante via cURL

```bash
# Remplacer localhost par l'IP/domaine de votre serveur
# Note: Ajuster le port si modifié dans docker-compose.yml
export ZAP_SERVER="http://votre-serveur.com:8093"

# Lancer un scan
curl -X POST "$ZAP_SERVER/scan" \
     -H "Content-Type: application/json" \
     -d '{
       "target_url": "https://mon-app.com",
       "login_url": "https://mon-app.com/login",
       "username": "testuser",
       "password": "testpass"
     }'

# Suivre le scan
curl "$ZAP_SERVER/scans"

# Télécharger le rapport
curl -O "$ZAP_SERVER/reports/scan_20240115_143022/html"
```

## 🔒 Sécurité

### Bonnes Pratiques

1. **Variables d'environnement** : Ne jamais commiter le fichier `.env`
2. **Accès réseau** : Restreindre l'accès aux ports ZAP en production
3. **Mots de passe** : Utiliser des comptes de test dédiés avec mots de passe forts
4. **Rapports** : Chiffrer les rapports contenant des données sensibles
5. **Nettoyage** : Nettoyer régulièrement les anciens rapports

### Configuration Sécurisée pour Production

```bash
# Créer un utilisateur dédié
sudo useradd -m -s /bin/bash zapscanner
sudo usermod -aG docker zapscanner

# Déployer avec des permissions restreintes
sudo -u zapscanner docker-compose up -d

# Limiter l'accès réseau (exemple avec iptables)
sudo iptables -A INPUT -p tcp --dport 8093 -s IP_AUTORISE -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8093 -j DROP
```

## 🐛 Dépannage

### Problèmes Courants

#### Service ne démarre pas
```bash
# Vérifier les logs
docker-compose logs zap-api
docker-compose logs zap

# Vérifier les ports
netstat -tuln | grep -E '8080|8093'

# Redémarrer proprement
docker-compose down && docker-compose up -d
```

#### Problèmes de connexion ZAP
```bash
# Tester la connectivité
docker-compose exec zap-api curl http://zap:8080/JSON/core/view/version/

# Vérifier que ZAP est prêt
docker-compose exec zap netstat -tuln | grep 8080
```

#### Erreurs SSL/TLS
```bash
# Vérifier les certificats dans le conteneur
docker-compose exec zap-api python -c "
import requests
import urllib3
urllib3.disable_warnings()
print(requests.get('https://httpbin.org/get', verify=False).status_code)
"
```

#### Problèmes de performance
```bash
# Monitoring des ressources
docker stats

# Ajuster les limites dans docker-compose.yml
services:
  zap:
    mem_limit: 2g
    cpus: '1.0'
```

### Support et Logs

```bash
# Collecter tous les logs pour debug
docker-compose logs --no-color > debug_logs.txt

# Informations système
docker version
docker-compose version
docker system info
```

## 📚 Ressources Additionnelles

- [Documentation OWASP ZAP](https://www.zaproxy.org/docs/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [ZAP API Documentation](https://www.zaproxy.org/docs/api/)

## 🤝 Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push sur la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

**⚠️ Avertissement** : Cet outil est conçu pour tester la sécurité de vos propres applications ou d'applications pour lesquelles vous avez une autorisation explicite. L'utilisation de cet outil sur des applications sans autorisation peut être illégale.