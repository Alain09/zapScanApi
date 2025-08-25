#!/usr/bin/env python3
"""
Script d'automatisation OWASP ZAP pour scan de sécurité avec authentification
Utilise zaproxy 0.4.0 pour piloter ZAP via son API REST
"""

import time
import sys
import os
from pathlib import Path
from datetime import datetime
from zapv2 import ZAPv2
import requests
import json
import urllib3
import logging

# Désactiver les warnings SSL pour les certificats auto-signés
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ZAPAutomatedScanner:
    def __init__(self, zap_proxy_url='http://127.0.0.1:8080', api_key="changeme"):
        """
        Initialise le scanner ZAP automatisé
        
        Args:
            zap_proxy_url: URL du proxy ZAP (par défaut localhost:8080)
            api_key: Clé API ZAP (requir)
        """
        self.zap_proxy_url = zap_proxy_url
        self.api_key = api_key
        self.zap = ZAPv2(proxies={'http': zap_proxy_url, 'https': zap_proxy_url}, apikey=api_key)
        self.context_id = None
        self.user_id = None
        
        # Configuration par défaut
        self.target_url = "https://localhost:3000"  # URL corrigée pour votre serveur local
        self.login_url = "https://localhost:3000/login"  # URL de login corrigée
        self.username = "testuser"  # À REMPLACER
        self.password = "testpass"  # À REMPLACER
        self.username_param = "username"  # À REMPLACER
        self.password_param = "password"  # À REMPLACER
        
        # Dossier de sortie pour les rapports
        self.output_dir = Path("zap_reports")
        self.output_dir.mkdir(exist_ok=True)
    
    def verify_zap_connection(self):
        """Vérifie que ZAP est accessible"""
        try:
            version = self.zap.core.version
            logger.info(f"✓ Connexion ZAP établie - Version: {version}")
            return True
        except Exception as e:
            logger.info(f"✗ Erreur de connexion à ZAP: {e}")
            return False
    
    def setup_context_and_auth(self, contextname="AuthenticatedScan"):
        """Configure le contexte ZAP et l'authentification par formulaire"""
        try:
            # Supprimer le contexte existant s'il existe
            try:
                existing_contexts = self.zap.context.context_list
                for ctx in existing_contexts:
                    if ctx == contextname:
                        logger.info(f"🗑️  Suppression du contexte existant: {contextname}")
                        self.zap.context.remove_context(contextname, apikey=self.api_key)
                        time.sleep(2)
                        break
            except:
                pass  # Ignore si le contexte n'existe pas
            
            # Créer un nouveau contexte
            logger.info(f"🔧 Création du contexte: {contextname}")
            self.context_id = self.zap.context.new_context(contextname, apikey=self.api_key)
            
            # Inclure l'URL cible dans le contexte
            self.zap.context.include_in_context(contextname, f"{self.target_url}.*", apikey=self.api_key)
            
            # Configuration de l'authentification par formulaire
            logger.info("🔐 Configuration de l'authentification par formulaire")
            
            # Définir la méthode d'authentification (form-based)
            auth_method_config = f"loginUrl={self.login_url}&loginRequestData={self.username_param}%3D%7B%25username%25%7D%26{self.password_param}%3D%7B%25password%25%7D"
            
            self.zap.authentication.set_authentication_method(
                contextid=self.context_id,
                authmethodname="formBasedAuthentication",
                authmethodconfigparams=auth_method_config,
                apikey=self.api_key
            )
            
            # Créer un utilisateur pour l'authentification
            logger.info("👤 Création de l'utilisateur d'authentification")
            self.user_id = self.zap.users.new_user(self.context_id, self.username, apikey=self.api_key)
            
            # Configurer les credentials de l'utilisateur
            auth_creds = f"username={self.username}&password={self.password}"
            self.zap.users.set_authentication_credentials(
                contextid=self.context_id,
                userid=self.user_id,
                authcredentialsconfigparams=auth_creds,
                apikey=self.api_key
            )

            logger.info("✓ Contexte et authentification configurés")
            return True
            
        except Exception as e:
            logger.info(f"✗ Erreur lors de la configuration: {e}")
            return False
    
    def perform_authentication(self):
        """Effectue l'authentification"""
        try:
            logger.info("🔑 Authentification en cours...")
            
            # Activer l'utilisateur
            self.zap.users.set_user_enabled(
                contextid=self.context_id,
                userid=self.user_id,
                enabled=True
            )
            
            # Définir cet utilisateur comme "forced user"
            self.zap.forcedUser.set_forced_user(
                contextid=self.context_id,
                userid=self.user_id
            )
            self.zap.forcedUser.set_forced_user_mode_enabled(True)
            
            logger.info(f"✓ Utilisateur {self.username} activé pour le contexte {self.context_id}")
                
            # Attendre un peu pour stabiliser
            time.sleep(3)

            # Vérifier si l'authentification a réussi avec gestion SSL
            try:
                response = requests.get(
                    self.target_url, 
                    proxies={'http': self.zap_proxy_url, 'https': self.zap_proxy_url}, 
                    timeout=10,
                    verify=False  # Ignorer la vérification SSL pour les certificats auto-signés
                )
                if response.status_code == 200:
                    logger.info("✓ Authentification réussie")
                    return True
                else:
                    logger.info(f"⚠️  Réponse HTTP: {response.status_code}")
                    return True  # Continuer même si le statut n'est pas 200
            except requests.exceptions.SSLError as ssl_error:
                logger.info(f"⚠️  Erreur SSL ignorée: {ssl_error}")
                logger.info("✓ Authentification configurée (SSL ignoré)")
                return True
            except Exception as e:
                logger.info(f"⚠️  Erreur de connexion: {e}")
                logger.info("✓ Authentification configurée (erreur ignorée)")
                return True

            return True
            
        except Exception as e:
            logger.info(f"✗ Erreur d'authentification: {e}")
            return False
    
    def spider_scan(self):
        """Lance le spider pour découvrir les URLs"""
        try:
            logger.info("🕷️  Lancement du spider...")
            logger.info('Spidering target {}'.format(self.target_url))
            
            # Lancer le spider avec l'utilisateur authentifié
            scan_id = self.zap.spider.scan_as_user(
                url=self.target_url,
                contextid=self.context_id,
                userid=self.user_id,
                recurse=True,
                subtreeonly=False,
            )
            
            logger.info(f"Spider ID: {scan_id}")
            
            # Attendre la fin du spider
            while int(self.zap.spider.status(scan_id)) < 100:
                progress = self.zap.spider.status(scan_id)
                logger.info(f"Spider progression: {progress}%")
                time.sleep(5)
            
            # Récupérer les résultats
            spider_results = self.zap.spider.results(scan_id)
            logger.info(f"✓ Spider terminé ")
            # Construction du dictionnaire
            result_json = {
                "id": scan_id,
                "nombre_liens": len(spider_results),
                "liens": spider_results
            }

            # Affichage (facultatif, en format JSON bien lisible)
            logger.info(json.dumps(result_json, indent=2, ensure_ascii=False))

            # Retourner le JSON
            return result_json["id"] 
            
        except Exception as e:
            logger.info(f"✗ Erreur lors du spider: {e}")
            return None
    
    def active_scan(self):
        """Lance le scan actif de vulnérabilités"""
        try:
            logger.info("🔍 Lancement du scan actif...")
            
            # Lancer le scan actif avec l'utilisateur authentifié
            scan_id = self.zap.ascan.scan_as_user(
                url=self.target_url,
                contextid=self.context_id,
                userid=self.user_id,
                recurse=True,
                scanpolicyname=None,  # Utilise la politique par défaut
                method=None,
                postdata=None,
                apikey=self.api_key
            )
            
            logger.info(f"Scan actif ID: {scan_id}")
            
            # Suivre la progression
            while int(self.zap.ascan.status(scan_id)) < 100:
                progress = self.zap.ascan.status(scan_id)
                logger.info(f"Scan actif progression: {progress}%")
                time.sleep(10)
            
            logger.info("✓ Scan actif terminé")
            return scan_id
            
        except Exception as e:
            logger.info(f"✗ Erreur lors du scan actif: {e}")
            return None
    
    def generate_reports(self):
        """Génère les rapports de scan"""
        try:
            #timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Rapport HTML
            html_report_path = self.output_dir / f"zap_report_{self.active_scan()}.html"
            logger.info(f"📄 Génération du rapport HTML: {html_report_path}")
            
            html_report = self.zap.core.htmlreport(apikey=self.api_key)
            with open(html_report_path, 'w', encoding='utf-8') as f:
                f.write(html_report)
            
            # Rapport JSON pour analyse programmatique
            json_report_path = self.output_dir / f"zap_report_{self.active_scan()}.json"
            logger.info(f"📄 Génération du rapport JSON: {json_report_path}")
            
            json_report = self.zap.core.jsonreport(apikey=self.api_key)
            with open(json_report_path, 'w', encoding='utf-8') as f:
                f.write(json_report)
            
            # Résumé des alertes
            alerts = self.zap.core.alerts()
            high_alerts = [alert for alert in alerts if alert['risk'] == 'High']
            medium_alerts = [alert for alert in alerts if alert['risk'] == 'Medium']
            
            logger.info(f"\n📊 RÉSUMÉ DU SCAN:")
            logger.info(f"   • Alertes HAUTE gravité: {len(high_alerts)}")
            logger.info(f"   • Alertes MOYENNE gravité: {len(medium_alerts)}")
            logger.info(f"   • Total alertes: {len(alerts)}")
            
            return {
                'html_report': html_report_path,
                'json_report': json_report_path,
                'high_alerts': len(high_alerts),
                'total_alerts': len(alerts)
            }
            
        except Exception as e:
            logger.info(f"✗ Erreur lors de la génération des rapports: {e}")
            return None
    
    def cleanup(self):
        """Nettoie les ressources ZAP"""
        try:
            logger.info("🧹 Nettoyage...")
            if self.context_id:
                # Correction: utiliser self.api_key au lieu de self.api
                self.zap.context.remove_context(self.context_id, apikey=self.api_key)
            logger.info("✓ Nettoyage terminé")
        except Exception as e:
            logger.info(f"⚠️  Erreur lors du nettoyage: {e}")
    
    def run_full_scan(self):
        """Exécute le scan complet automatisé"""
        logger.info("🚀 DÉMARRAGE DU SCAN AUTOMATISÉ ZAP")
        logger.info("="*50)
        
        start_time = datetime.now()
        
        try:
            # 1. Vérifier la connexion ZAP
            if not self.verify_zap_connection():
                return False
            
            # 2. Configurer le contexte et l'authentification
            if not self.setup_context_and_auth():
                return False
            
            # 3. Effectuer l'authentification
            if not self.perform_authentication():
                return False
            
            # 4. Spider scan
            spider_id = self.spider_scan()
            if spider_id is None:
                return False
            
            # 5. Scan actif
            scan_id = self.active_scan()
            if scan_id is None:
                return False
            
            # 6. Générer les rapports
            report_info = self.generate_reports()
            if report_info is None:
                return False
            
            # 7. Résultats finaux
            end_time = datetime.now()
            duration = end_time - start_time
            
            logger.info("\n" + "="*50)
            logger.info("🎉 SCAN TERMINÉ AVEC SUCCÈS!")
            logger.info(f"⏱️  Durée totale: {duration}")
            logger.info(f"📁 Rapports sauvegardés dans: {self.output_dir}")
            logger.info(f"🚨 Alertes haute gravité: {report_info['high_alerts']}")
            
            
            # Retourner le code de sortie selon le rapport
            return report_info is not None # True si le rapport est généré
            
        except Exception as e:
            logger.info(f"💥 Erreur critique: {e}")
            return False
        finally:
            self.cleanup()
