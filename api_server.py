from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, HttpUrl, Field
import uvicorn
import os
import glob
import json
import logging
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Import de votre scanner
from zap_scanner import ZAPAutomatedScanner

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="OWASP ZAP Scanner API",
    description="API REST pour automatiser les scans de sécurité OWASP ZAP",
    version="1.0.0"
)

# Configuration depuis les variables d'environnement
class Config:
    # Configuration ZAP par défaut
    DEFAULT_ZAP_PROXY_URL = os.getenv("ZAP_PROXY_URL", "http://127.0.0.1:8080")
    DEFAULT_ZAP_API_KEY = os.getenv("ZAP_API_KEY")
    
    # Configuration application de test par défaut
    DEFAULT_TARGET_URL = os.getenv("TARGET_URL", "https://localhost:3000")
    DEFAULT_LOGIN_URL = os.getenv("LOGIN_URL", "https://localhost:3000/login")
    DEFAULT_USERNAME = os.getenv("TEST_USERNAME", "testuser")
    DEFAULT_PASSWORD = os.getenv("TEST_PASSWORD", "testpass")
    DEFAULT_USERNAME_PARAM = os.getenv("USERNAME_PARAM", "username")
    DEFAULT_PASSWORD_PARAM = os.getenv("PASSWORD_PARAM", "password")
    
    # Configuration API
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "8000"))
    LOG_LEVEL = os.getenv("LOG_LEVEL", "info")
    
    # Configuration rapports
    REPORTS_DIR = os.getenv("REPORTS_DIR", "zap_reports")
    MAX_REPORTS_RETENTION = int(os.getenv("MAX_REPORTS_RETENTION", "30"))

class ScanRequest(BaseModel):
    # Paramètres requis
    target_url: HttpUrl
    login_url: HttpUrl
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=100)
    
    # Paramètres optionnels avec valeurs par défaut depuis .env
    username_param: Optional[str] = Field(default=None, min_length=1)
    password_param: Optional[str] = Field(default=None, min_length=1)
    zap_proxy_url: Optional[HttpUrl] = Field(default=None)
    zap_api_key: Optional[str] = Field(default=None, min_length=10)

    class Config:
        schema_extra = {
            "example": {
                "target_url": "https://example.com",
                "login_url": "https://example.com/login",
                "username": "testuser",
                "password": "testpass",
                "username_param": "email",
                "password_param": "password"
            }
        }

class QuickScanRequest(BaseModel):
    """Modèle pour un scan rapide avec valeurs par défaut du .env"""
    target_url: Optional[HttpUrl] = Field(default=None)
    login_url: Optional[HttpUrl] = Field(default=None)
    username: Optional[str] = Field(default=None, min_length=1)
    password: Optional[str] = Field(default=None, min_length=1)

# Stockage en mémoire des scans
scans = {}

def get_config_value(request_value, env_default, fallback):
    """Utilitaire pour récupérer une valeur avec priorité : request > env > fallback"""
    return request_value or env_default or fallback

@app.post("/scan", summary="Démarrer un nouveau scan de sécurité")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Lance un nouveau scan de sécurité OWASP ZAP avec authentification.
    Utilise les valeurs du fichier .env si certains paramètres ne sont pas fournis.
    """
    try:
        # Validation de la clé API ZAP (obligatoire)
        zap_api_key = get_config_value(req.zap_api_key, Config.DEFAULT_ZAP_API_KEY, None)
        if not zap_api_key:
            raise HTTPException(
                status_code=400, 
                detail="Clé API ZAP requise (paramètre zap_api_key ou variable ZAP_API_KEY dans .env)"
            )
        
        # Configuration avec priorité : paramètre > .env > défaut
        scan_config = {
            "target_url": str(req.target_url),
            "login_url": str(req.login_url),
            "username": req.username,
            "password": req.password,
            "username_param": get_config_value(req.username_param, Config.DEFAULT_USERNAME_PARAM, "username"),
            "password_param": get_config_value(req.password_param, Config.DEFAULT_PASSWORD_PARAM, "password"),
            "zap_proxy_url": str(get_config_value(req.zap_proxy_url, Config.DEFAULT_ZAP_PROXY_URL, "http://127.0.0.1:8080")),
            "zap_api_key": zap_api_key
        }
        
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(scan_config['target_url'])}"
        scans[scan_id] = {
            "status": "initializing", 
            "report": None,
            "started_at": datetime.now().isoformat(),
            "config": {k: v for k, v in scan_config.items() if k != "zap_api_key"}  # Ne pas exposer la clé API
        }
        
        def run_scan():
            try:
                scans[scan_id]["status"] = "running"
                logger.info(f"Démarrage du scan {scan_id} pour {scan_config['target_url']}")
                
                scanner = ZAPAutomatedScanner(
                    zap_proxy_url=scan_config["zap_proxy_url"], 
                    api_key=scan_config["zap_api_key"]
                )
                
                # Configuration du scanner
                scanner.target_url = scan_config["target_url"]
                scanner.login_url = scan_config["login_url"]
                scanner.username = scan_config["username"]
                scanner.password = scan_config["password"]
                scanner.username_param = scan_config["username_param"]
                scanner.password_param = scan_config["password_param"]
                
                success = scanner.run_full_scan()
                
                scans[scan_id].update({
                    "status": "completed" if success else "failed",
                    "report_dir": str(scanner.output_dir),
                    "completed_at": datetime.now().isoformat()
                })
                
                logger.info(f"Scan {scan_id} terminé: {success}")
                
            except Exception as e:
                logger.error(f"Erreur lors du scan {scan_id}: {str(e)}")
                scans[scan_id].update({
                    "status": "error",
                    "error": str(e),
                    "failed_at": datetime.now().isoformat()
                })

        background_tasks.add_task(run_scan)
        return {"scan_id": scan_id, "status": "started", "message": "Scan démarré avec succès"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.post("/quick-scan", summary="Démarrer un scan avec configuration par défaut")
async def quick_scan(req: QuickScanRequest, background_tasks: BackgroundTasks):
    """
    Lance un scan rapide en utilisant principalement les valeurs du fichier .env.
    Utile pour tester rapidement votre application de développement.
    """
    try:
        # Vérifier que les valeurs essentielles sont disponibles
        if not Config.DEFAULT_ZAP_API_KEY:
            raise HTTPException(
                status_code=400,
                detail="ZAP_API_KEY manquante dans le fichier .env"
            )
        
        # Construire la requête complète avec les valeurs par défaut
        full_request = ScanRequest(
            target_url=req.target_url or Config.DEFAULT_TARGET_URL,
            login_url=req.login_url or Config.DEFAULT_LOGIN_URL,
            username=req.username or Config.DEFAULT_USERNAME,
            password=req.password or Config.DEFAULT_PASSWORD,
            username_param=Config.DEFAULT_USERNAME_PARAM,
            password_param=Config.DEFAULT_PASSWORD_PARAM,
            zap_proxy_url=Config.DEFAULT_ZAP_PROXY_URL,
            zap_api_key=Config.DEFAULT_ZAP_API_KEY
        )
        
        return await start_scan(full_request, background_tasks)
        
    except Exception as e:
        logger.error(f"Erreur quick-scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")

@app.get("/config", summary="Afficher la configuration actuelle")
async def get_config():
    """
    Affiche la configuration actuelle (sans les secrets).
    Utile pour déboguer la configuration.
    """
    return {
        "zap": {
            "proxy_url": Config.DEFAULT_ZAP_PROXY_URL,
            "api_key_configured": bool(Config.DEFAULT_ZAP_API_KEY)
        },
        "defaults": {
            "target_url": Config.DEFAULT_TARGET_URL,
            "login_url": Config.DEFAULT_LOGIN_URL,
            "username": Config.DEFAULT_USERNAME,
            "username_param": Config.DEFAULT_USERNAME_PARAM,
            "password_param": Config.DEFAULT_PASSWORD_PARAM
        },
        "api": {
            "host": Config.API_HOST,
            "port": Config.API_PORT,
            "log_level": Config.LOG_LEVEL
        },
        "reports": {
            "directory": Config.REPORTS_DIR,
            "max_retention": Config.MAX_REPORTS_RETENTION
        }
    }

@app.get("/scan/{scan_id}", summary="Obtenir le statut d'un scan")
async def get_scan_status(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    return scans[scan_id]

@app.get("/scans", summary="Lister tous les scans")
async def list_scans():
    return {"total": len(scans), "scans": scans}

@app.get("/last-report/html", summary="Télécharger le dernier rapport HTML")
def get_last_report_html():
    reports_dir = Config.REPORTS_DIR
    if not os.path.exists(reports_dir):
        raise HTTPException(status_code=404, detail="Dossier de rapports introuvable")
    
    files = glob.glob(os.path.join(reports_dir, "*.html"))
    if not files:
        raise HTTPException(status_code=404, detail="Aucun rapport HTML trouvé")
    
    latest_file = max(files, key=os.path.getmtime)
    return FileResponse(
        latest_file,
        media_type="text/html",
        filename=os.path.basename(latest_file)
    )

@app.get("/last-report/json", summary="Obtenir le dernier rapport JSON")
def get_last_report_json():
    reports_dir = Config.REPORTS_DIR
    if not os.path.exists(reports_dir):
        raise HTTPException(status_code=404, detail="Dossier de rapports introuvable")
    
    files = glob.glob(os.path.join(reports_dir, "*.json"))
    if not files:
        raise HTTPException(status_code=404, detail="Aucun rapport JSON trouvé")
    
    latest_file = max(files, key=os.path.getmtime)
    
    try:
        with open(latest_file, 'r', encoding='utf-8') as f:
            json_content = json.load(f)
        
        file_stats = os.stat(latest_file)
        modified_datetime = datetime.fromtimestamp(file_stats.st_mtime)
        
        return JSONResponse(content={
            "metadata": {
                "filename": os.path.basename(latest_file),
                "file_size": file_stats.st_size,
                "modified": modified_datetime.isoformat(),
            },
            "report": json_content
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")

@app.get("/health", summary="Vérification de l'état de l'API")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "zap_configured": bool(Config.DEFAULT_ZAP_API_KEY)
    }

if __name__ == "__main__":
    uvicorn.run(
        app, 
        host=Config.API_HOST, 
        port=Config.API_PORT,
        reload=True,
        log_level=Config.LOG_LEVEL
    )