"""
Agent d'analyse de liens qui évalue les URLs et les pièces jointes 
pour détecter les menaces potentielles.
"""

import logging
import re
import urllib.parse
from typing import Dict, Any, List, Optional
import json
from pydantic import BaseModel, Field

from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from tools.sandbox_api import SandboxAPI

logger = logging.getLogger(__name__)

# Liste de TLDs suspects ou connus pour héberger du contenu malveillant
SUSPICIOUS_TLDS = [
    'xyz', 'top', 'club', 'work', 'gq', 'ml', 'cf', 'tk', 'ga'
]

# Modèles d'URL potentiellement malveillants
SUSPICIOUS_URL_PATTERNS = [
    r'bit\.ly',
    r'tinyurl\.com',
    r'goo\.gl',
    r'is\.gd',
    r'cl\.ly',
    r'adf\.ly',
    r't\.co',
    r'tiny\.cc',
    r'ow\.ly',
    r'rebrandly',
    r'cutt\.ly',
    r'random\d+\.com',
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # Adresses IP
    r'file\.exe$',
    r'file\.zip$',
    r'file\.rar$',
    r'file\.js$',
    r'bank',
    r'secure',
    r'account',
    r'update',
    r'verify',
    r'wallet',
    r'confirm',
    r'login',
    r'password'
]

class LinkAnalysisResult(BaseModel):
    """Format du résultat de l'analyse de lien"""
    url: str = Field(description="URL analysée")
    is_suspicious: bool = Field(description="Indique si l'URL est considérée comme suspecte")
    threat_level: float = Field(description="Niveau de menace entre 0.0 (sûr) et 1.0 (critique)")
    reasons: List[str] = Field(description="Raisons de la classification")
    is_redirector: bool = Field(description="Indique si l'URL est un service de redirection")
    domain_analysis: str = Field(description="Analyse du domaine")
    path_analysis: str = Field(description="Analyse du chemin d'accès")
    recommendations: List[str] = Field(description="Recommandations concernant cette URL")

class AttachmentAnalysisResult(BaseModel):
    """Format du résultat de l'analyse de pièce jointe"""
    filename: str = Field(description="Nom du fichier")
    mime_type: str = Field(description="Type MIME")
    is_suspicious: bool = Field(description="Indique si la pièce jointe est considérée comme suspecte")
    threat_level: float = Field(description="Niveau de menace entre 0.0 (sûr) et 1.0 (critique)")
    reasons: List[str] = Field(description="Raisons de la classification")
    file_type_risk: str = Field(description="Niveau de risque associé à ce type de fichier")
    sandbox_result: Optional[str] = Field(None, description="Résultat de l'analyse en sandbox")
    recommendations: List[str] = Field(description="Recommandations concernant cette pièce jointe")

class BulkLinkAnalysisResult(BaseModel):
    """Format du résultat de l'analyse groupée de liens"""
    links_analyzed: List[LinkAnalysisResult] = Field(description="Résultats d'analyse pour chaque lien")
    overall_threat_score: float = Field(description="Score de menace global pour tous les liens")