# Scanner de Sécurité OWASP ZAP Automatisé

Un outil d'automatisation pour effectuer des scans de sécurité avec OWASP ZAP, incluant l'authentification par formulaire et une API REST pour l'intégration CI/CD.

## 🔧 Fonctionnalités

- **Scan automatisé complet** : Spider + Scan actif avec authentification
- **Gestion de l'authentification** : Support des formulaires de connexion
- **API REST** : Interface pour déclencher des scans à distance
- **Configuration flexible** : Fichier .env pour la gestion sécurisée des paramètres
- **Rapports multiples** : Génération de rapports HTML et JSON
- **Gestion SSL** : Support des certificats auto-signés
- **Documentation interactive** : Interface Swagger/OpenAPI automatique

## 📁 Structure du Projet

```
zap-scanner/
├── .env.example            # Template de configuration
├── .env                    # Configuration (ne pas commiter)
├── .gitignore             # Fichiers à ignorer par Git
├── zap_scanner.py         # Script principal de scan
├── api_zap.py             # API REST FastAPI
├── requirements.txt       # Dépendances Python
├── zap_reports/           # Dossier des rapports générés (ignoré par Git)
├── README.md              # Ce fichier
└── docs/                  # Documentation additionnelle (optionnel)
```

## 🚀 Installation

### Prérequis

1. **OWASP ZAP** installé et fonctionnel
   - Télécharger depuis [zaproxy.org](https://www.zaproxy.org/download/)
   - Version recommandée : 2.12.0 ou plus récente

2. **Python 3.7+** installé

### Installation Rapide

```bash
# 1. Cloner ou télécharger le projet
cd zap-scanner

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Configurer l'environnement
cp .env.example .env
# Éditer le fichier .env avec vos vraies valeurs

# 4. Démarrer OWASP ZAP
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# 5. Lancer l'API
python api_zap.py
```

## ⚙️ Configuration

### 1. Fichier .env

Créez un fichier `.env` à partir du template :

```bash
cp .env.example .env
```

Éditez le fichier `.env` avec vos paramètres :

```env
# === Configuration OWASP ZAP ===
ZAP_PROXY_URL=http://127.0.0.1:8080
ZAP_API_KEY=your-zap-api-key-here

# === Configuration Application de Test ===
TARGET_URL=https://localhost:3000
LOGIN_URL=https://localhost:3000/login
TEST_USERNAME=testuser
TEST_PASSWORD=testpass
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

### 2. Obtenir la Clé API ZAP

#### Méthode 1: Via l'interface ZAP
1. Ouvrir OWASP ZAP GUI
2. Aller dans **Tools** → **Options** → **API**
3. Cliquer sur **Generate API Key**
4. Copier la clé dans votre fichier `.env`

#### Méthode 2: Via l'API
```bash
curl http://127.0.0.1:8080/JSON/core/view/generateApiKey/
```

### 3. Démarrer OWASP ZAP

#### Mode Daemon (Recommandé pour l'automatisation)
```bash
# Linux/Mac
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# Windows
zap.bat -daemon -host 127.0.0.1 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

#### Mode GUI (Pour le développement)
```bash
zap.sh -host 127.0.0.1 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

## 🎯 Utilisation

### Mode API REST (Recommandé)

#### 1. Démarrer l'API
```bash
python api_zap.py
```

L'API sera accessible sur `http://localhost:8000`

#### 2. Documentation Interactive
Accédez à la documentation Swagger : `http://localhost:8000/docs`

#### 3. Vérifier la Configuration
```bash
curl http://localhost:8000/config
```

#### 4. Scan Rapide (avec valeurs .env)
```bash
curl -X POST "http://localhost:8000/quick-scan" \
     -H "Content-Type: application/json" \
     -d "{}"
```

#### 5. Scan Personnalisé
```bash
curl -X POST "http://localhost:8000/scan" \
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

#### 6. Suivre le Scan
```bash
# Obtenir le scan_id de la réponse précédente
curl "http://localhost:8000/scan/{scan_id}"
```

#### 7. Récupérer les Rapports
```bash
# Rapport JSON via API
curl "http://localhost:8000/last-report/json"

# Télécharger le rapport HTML
curl -O "http://localhost:8000/last-report/html"
```

### Mode Script Direct

```python
from zap_scanner import ZAPAutomatedScanner

def main():
    scanner = ZAPAutomatedScanner(
        zap_proxy_url="http://127.0.0.1:8080",
        api_key="votre-cle-api"
    )
    
    # Configuration
    scanner.target_url = "https://votre-app.com"
    scanner.login_url = "https://votre-app.com/login"
    scanner.username = "testuser"
    scanner.password = "testpass"
    
    # Lancer le scan
    success = scanner.run_full_scan()
    return success

if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)
```

## 📊 Endpoints API

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/docs` | Documentation Swagger interactive |
| `GET` | `/health` | État de santé de l'API |
| `GET` | `/config` | Configuration actuelle (sans secrets) |
| `POST` | `/scan` | Démarrer un scan personnalisé |
| `POST` | `/quick-scan` | Scan rapide avec config .env |
| `GET` | `/scan/{scan_id}` | Statut d'un scan spécifique |
| `GET` | `/scans` | Liste de tous les scans |
| `GET` | `/last-report/html` | Télécharger dernier rapport HTML |
| `GET` | `/last-report/json` | Dernier rapport JSON via API |

## 📄 Format des Rapports

### Rapport JSON
```json
{
  "metadata": {
    "filename": "zap_report_20240115_143022.json",
    "file_size": 15234,
    "generated_at": "2024-01-15 14:30:22"
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

## 🔒 Sécurité

### Bonnes Pratiques
1. **Ne jamais commiter le fichier `.env`**
2. **Utiliser des mots de passe forts** pour les comptes de test
3. **Restreindre l'accès à l'API** en production
4. **Chiffrer les rapports** contenant des données sensibles
5. **Nettoyer régulièrement** les anciens rapports

### Variables Sensibles
Ces informations ne doivent **jamais** être dans votre code :
- Clés API ZAP
- Mots de passe de test
- URLs d'environnements de production
- Certificats et clés privées

## 🚀 Intégration CI/CD

### Exemple GitLab CI
```yaml
zap_scan:
  stage: security_test
  image: python:3.9
  services:
    - name: owasp/zap2docker-stable
      alias: zap
  variables:
    ZAP_PROXY_URL: "http://zap:8080"
  script:
    - pip install -r requirements.txt
    - python -c "
        import requests, time
        from api_zap import app
        # Attendre que ZAP soit prêt
        for i in range(30):
            try:
                requests.get('http://zap:8080')
                break
            except:
                time.sleep(2)
        # Lancer le scan
        # ... votre code de scan
      "
  artifacts:
    reports:
      junit: zap_reports/*.xml
    paths:
      - zap_reports/
    when: always
```

### Exemple GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  zap_scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
        
    - name: Install dependencies
      run: pip install -r requirements.txt
      
    - name: Start ZAP
      run: |
        docker run -d --name zap -p 8080:8080 \
          owasp/zap2docker-stable \
          zap.sh -daemon -host 0.0.0.0 -port 8080
          
    - name: Wait for ZAP
      run: |
        timeout 60 sh -c 'until nc -z localhost 8080; do sleep 1; done'
        
    - name: Run Security Scan
      env:
        ZAP_PROXY_URL: http://localhost:8080
        ZAP_API_KEY: ${{ secrets.ZAP_API_KEY }}
        TARGET_URL: ${{ secrets.TARGET_URL }}
      run: python zap_scanner.py
      
    - name: Upload Reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: zap-reports
        path: zap_reports/
```

## 🐛 Dépannage

### Problèmes Courants

#### 1. Erreur de connexion à ZAP
```bash
# Vérifier que ZAP fonctionne
curl http://127.0.0.1:8080/JSON/core/view/