from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, HttpUrl, Field
import uvicorn
import os
import glob
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict
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

class ReportInfo(BaseModel):
    """Modèle pour les informations d'un rapport"""
    report_id: str
    scan_id: Optional[str]
    filename: str
    file_type: str  # "html" ou "json"
    size: int
    created_at: str
    target_url: Optional[str]

# Stockage en mémoire des scans
scans = {}

def get_config_value(request_value, env_default, fallback):
    """Utilitaire pour récupérer une valeur avec priorité : request > env > fallback"""
    return request_value or env_default or fallback

def extract_report_id_from_filename(filename: str) -> str:
    """Extrait l'ID du rapport depuis le nom de fichier"""
    # Assume que les fichiers suivent le format: scan_YYYYMMDD_HHMMSS_hash.ext
    base_name = os.path.splitext(filename)[0]
    return base_name

def get_all_reports() -> List[Dict]:
    """Récupère tous les rapports disponibles dans le dossier zap_reports, groupés par report_id"""
    reports_dict = {}
    reports_dir = Config.REPORTS_DIR
    
    if not os.path.exists(reports_dir):
        return []
    
    # Chercher tous les fichiers HTML et JSON
    for file_type in ["html", "json"]:
        pattern = os.path.join(reports_dir, f"*.{file_type}")
        files = glob.glob(pattern)
        
        for file_path in files:
            try:
                filename = os.path.basename(file_path)
                report_id = extract_report_id_from_filename(filename)
                file_stats = os.stat(file_path)
                created_at = datetime.fromtimestamp(file_stats.st_ctime).isoformat()
                
                # Si c'est la première fois qu'on voit ce report_id, l'initialiser
                if report_id not in reports_dict:
                    # Essayer de trouver le scan_id correspondant
                    scan_id = None
                    target_url = None
                    for sid, scan_data in scans.items():
                        if scan_data.get("report") and report_id in scan_data["report"]:
                            scan_id = sid
                            target_url = scan_data.get("config", {}).get("target_url")
                            break
                    
                    reports_dict[report_id] = {
                        "report_id": report_id,
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "created_at": created_at,
                        "formats_available": [],
                        "files": []
                    }
                
                # Ajouter le fichier à la liste
                reports_dict[report_id]["formats_available"].append(file_type)
                reports_dict[report_id]["files"].append({
                    "type": file_type,
                    "filename": filename,
                    "size": file_stats.st_size,
                    "created_at": created_at
                })
                
                # Garder la date la plus récente comme date de création du rapport
                if created_at > reports_dict[report_id]["created_at"]:
                    reports_dict[report_id]["created_at"] = created_at
                    
            except Exception as e:
                logger.warning(f"Erreur lors du traitement du fichier {file_path}: {e}")
                continue
    
    # Convertir en liste et trier par date de création (plus récent en premier)
    reports = list(reports_dict.values())
    reports.sort(key=lambda x: x["created_at"], reverse=True)
    
    return reports

def find_report_file(report_id: str, file_type: str = None) -> Optional[str]:
    """Trouve le fichier de rapport correspondant à l'ID"""
    reports_dir = Config.REPORTS_DIR
    
    if not os.path.exists(reports_dir):
        return None
    
    # Si file_type est spécifié, chercher seulement ce type
    if file_type:
        pattern = os.path.join(reports_dir, f"{report_id}.{file_type}")
        files = glob.glob(pattern)
        return files[0] if files else None
    
    # Sinon, chercher HTML et JSON
    for ext in ["html", "json"]:
        pattern = os.path.join(reports_dir, f"{report_id}.{ext}")
        files = glob.glob(pattern)
        if files:
            return files[0]
    
    return None

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
                    "report": str(scanner.output_dir),
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

@app.get("/reports", summary="Lister tous les rapports disponibles")
async def list_reports() -> Dict:
    """
    Récupère la liste de tous les rapports disponibles avec leurs métadonnées.
    """
    try:
        reports = get_all_reports()
        return {
            "total": len(reports),
            "reports": reports
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des rapports: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de la récupération des rapports: {str(e)}")

@app.get("/reports/{report_id}/html", summary="Télécharger un rapport HTML par ID")
async def get_report_html(report_id: str):
    """
    Télécharge le rapport HTML correspondant à l'ID spécifié.
    """
    try:
        file_path = find_report_file(report_id, "html")
        
        if not file_path:
            raise HTTPException(
                status_code=404, 
                detail=f"Rapport HTML avec l'ID '{report_id}' non trouvé"
            )
        
        if not os.path.exists(file_path):
            raise HTTPException(
                status_code=404, 
                detail=f"Fichier de rapport '{report_id}' introuvable sur le disque"
            )
        
        return FileResponse(
            file_path,
            media_type="text/html",
            filename=os.path.basename(file_path)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du rapport HTML {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/reports/{report_id}/json", summary="Obtenir un rapport JSON par ID")
async def get_report_json(report_id: str):
    """
    Récupère le rapport JSON correspondant à l'ID spécifié.
    """
    try:
        file_path = find_report_file(report_id, "json")
        
        if not file_path:
            raise HTTPException(
                status_code=404, 
                detail=f"Rapport JSON avec l'ID '{report_id}' non trouvé"
            )
        
        if not os.path.exists(file_path):
            raise HTTPException(
                status_code=404, 
                detail=f"Fichier de rapport '{report_id}' introuvable sur le disque"
            )
        
        with open(file_path, 'r', encoding='utf-8') as f:
            json_content = json.load(f)
        
        file_stats = os.stat(file_path)
        modified_datetime = datetime.fromtimestamp(file_stats.st_mtime)
        
        return JSONResponse(content={
            "metadata": {
                "report_id": report_id,
                "filename": os.path.basename(file_path),
                "file_size": file_stats.st_size,
                "modified": modified_datetime.isoformat(),
            },
            "report": json_content
        })
        
    except HTTPException:
        raise
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Fichier JSON corrompu")
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du rapport JSON {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/reports/{report_id}", summary="Obtenir les métadonnées d'un rapport par ID")
async def get_report_info(report_id: str):
    """
    Récupère les métadonnées d'un rapport spécifique par son ID.
    """
    try:
        reports = get_all_reports()
        
        # Chercher le rapport avec l'ID correspondant
        for report in reports:
            if report["report_id"] == report_id:
                return report
        
        raise HTTPException(
            status_code=404, 
            detail=f"Rapport avec l'ID '{report_id}' non trouvé"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des infos du rapport {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

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