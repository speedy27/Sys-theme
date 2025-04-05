#!/usr/bin/env python3
"""
Agentic Mail Guardian - Système multi-agent de détection de menaces par email

Ce script principal initialise et exécute le graphe d'agents pour surveiller,
analyser et signaler les menaces potentielles dans les emails.
"""

import os
import logging
from dotenv import load_dotenv
import argparse
from datetime import datetime

# Import des composants principaux
from graph.flow import create_agent_graph
from tools.gmail_watcher import GmailWatcher
from tools.mistral_llm import get_mistral_llm

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs/mail_guardian_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def setup_environment():
    """Charge les variables d'environnement et crée les dossiers nécessaires"""
    # Chargement des variables d'environnement
    load_dotenv()
    
    # Vérification des variables d'environnement essentielles
    required_vars = [
        "GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_REFRESH_TOKEN",
        "BEDROCK_API_KEY", "BEDROCK_REGION"
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logger.error(f"Variables d'environnement manquantes: {', '.join(missing_vars)}")
        logger.error("Veuillez créer un fichier .env avec les variables requises")
        return False
    
    # Création des dossiers nécessaires s'ils n'existent pas
    os.makedirs("logs", exist_ok=True)
    os.makedirs("memory/chroma", exist_ok=True)
    
    return True

def parse_arguments():
    """Parse les arguments de ligne de commande"""
    parser = argparse.ArgumentParser(description='Agentic Mail Guardian - Système de détection de menaces par email')
    parser.add_argument('--mode', choices=['watch', 'analyze', 'test'], default='watch',
                      help='Mode de fonctionnement: watch (surveillance continue), analyze (analyse un email spécifique), test (test du système)')
    parser.add_argument('--email-id', type=str, help='ID de l\'email à analyser (en mode analyze)')
    parser.add_argument('--debug', action='store_true', help='Active le mode debug avec logs détaillés')
    
    return parser.parse_args()

def main():
    """Fonction principale du programme"""
    # Configuration de l'environnement
    if not setup_environment():
        return 1
    
    # Analyse des arguments
    args = parse_arguments()
    
    # Configuration du niveau de log en fonction des arguments
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Mode debug activé")
    
    try:
        # Initialisation du LLM
        logger.info("Initialisation du modèle LLM Mistral...")
        llm = get_mistral_llm()
        
        # Création du graphe d'agents
        logger.info("Création du graphe d'agents...")
        agent_graph = create_agent_graph(llm=llm)
        
        # Exécution en fonction du mode choisi
        if args.mode == 'watch':
            logger.info("Démarrage de la surveillance des emails...")
            gmail_watcher = GmailWatcher()
            gmail_watcher.watch_inbox(agent_graph.invoke)
            
        elif args.mode == 'analyze':
            if not args.email_id:
                logger.error("L'ID de l'email est requis en mode 'analyze'")
                return 1
                
            logger.info(f"Analyse de l'email spécifique: {args.email_id}")
            gmail_watcher = GmailWatcher()
            email_data = gmail_watcher.get_email_by_id(args.email_id)
            
            if email_data:
                result = agent_graph.invoke({"email": email_data})
                logger.info(f"Résultat de l'analyse: {result}")
            else:
                logger.error(f"Email avec ID {args.email_id} non trouvé")
                
        elif args.mode == 'test':
            logger.info("Exécution du test du système...")
            # Exemple d'email de test
            test_email = {
                "sender": "contact@example.com",
                "subject": "Important: Mise à jour de votre compte",
                "body": "Veuillez cliquer sur ce lien pour mettre à jour vos informations de sécurité: http://suspicious-site.com/update",
                "date": "2023-10-25T14:30:00Z",
                "has_attachments": True,
                "attachments": [
                    {"filename": "update.docx", "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
                ],
                "links": ["http://suspicious-site.com/update"]
            }
            
            result = agent_graph.invoke({"email": test_email})
            logger.info(f"Résultat du test: {result}")
        
        logger.info("Exécution terminée avec succès")
        return 0
    
    except Exception as e:
        logger.exception(f"Une erreur est survenue: {str(e)}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)