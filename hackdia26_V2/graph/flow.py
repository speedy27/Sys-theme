"""
Graphe LangGraph pour coordonner les agents dans le système Agentic Mail Guardian.
Ce module définit la logique de flux et les transitions entre les différents agents.
"""

import logging
from typing import Dict, Any, List, Optional, Literal, cast, Union, TypedDict
from enum import Enum

# Importation de LangGraph
from langgraph.graph import StateGraph, START, END
#from langgraph.checkpoint import MemorySaver
# from langgraph.checkpoint import Checkpoint, CheckpointState
from pydantic import BaseModel, Field

# Importation des agents
from agents.link_analyzer import LinkAnalyzerAgent
from agents.nlp_analyzer import NLPAnalyzerAgent
from agents.report_generator import ReportGeneratorAgent

logger = logging.getLogger(__name__)

# Définition des états possibles pour le flux de travail
class WorkflowState(str, Enum):
    """États possibles du flux de travail"""
    INITIAL_SCAN = "initial_scan"
    ANALYZE_LINKS = "analyze_links"
    ANALYZE_ATTACHMENTS = "analyze_attachments"
    ANALYZE_LANGUAGE = "analyze_language"
    GENERATE_REPORT = "generate_report"
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    CRITICAL = "critical"

# Définition des modèles pour les structures de données du graphe
class ThreatInfo(BaseModel):
    """Information sur une menace détectée"""
    score: float = Field(default=0.0, description="Score de menace entre 0.0 (sûr) et 1.0 (menace critique)")
    reasons: List[str] = Field(default_factory=list, description="Raisons qui ont contribué au score de menace")

class LinkInfo(BaseModel):
    """Information sur un lien analysé"""
    url: str
    safe: Optional[bool] = None
    threat_details: Optional[str] = None
    score: float = Field(default=0.0, description="Score de menace du lien entre 0.0 et 1.0")

class AttachmentInfo(BaseModel):
    """Information sur une pièce jointe analysée"""
    filename: str
    mime_type: str
    safe: Optional[bool] = None
    threat_details: Optional[str] = None
    score: float = Field(default=0.0, description="Score de menace de la pièce jointe entre 0.0 et 1.0")

class EmailState(BaseModel):
    """État complet du traitement d'un email dans le système"""
    # Données d'entrée
    email: Dict[str, Any] = Field(..., description="Données de l'email à analyser")
    
    # Analyses effectuées
    initial_scan_complete: bool = Field(default=False, description="Indique si l'analyse initiale a été effectuée")
    links_analyzed: bool = Field(default=False, description="Indique si les liens ont été analysés")
    attachments_analyzed: bool = Field(default=False, description="Indique si les pièces jointes ont été analysées")
    language_analyzed: bool = Field(default=False, description="Indique si le langage a été analysé")
    
    # Résultats d'analyse
    content_threat: ThreatInfo = Field(default_factory=ThreatInfo, description="Évaluation de la menace basée sur le contenu")
    link_threat: ThreatInfo = Field(default_factory=ThreatInfo, description="Évaluation de la menace basée sur les liens")
    attachment_threat: ThreatInfo = Field(default_factory=ThreatInfo, description="Évaluation de la menace basée sur les pièces jointes")
    language_threat: ThreatInfo = Field(default_factory=ThreatInfo, description="Évaluation de la menace basée sur l'analyse du langage")
    
    # Détails supplémentaires
    analyzed_links: List[LinkInfo] = Field(default_factory=list, description="Informations sur les liens analysés")
    analyzed_attachments: List[AttachmentInfo] = Field(default_factory=list, description="Informations sur les pièces jointes analysées")
    
    # Urgence et priorité
    urgency_level: int = Field(default=0, description="Niveau d'urgence de 0 (faible) à 5 (critique)")
    
    # Résultat final
    overall_threat_score: float = Field(default=0.0, description="Score global de menace")
    final_assessment: str = Field(default="", description="Évaluation finale du mail")
    recommendations: List[str] = Field(default_factory=list, description="Recommandations d'actions")

def create_agent_graph(llm):
    """
    Crée et configure le graphe d'agents pour l'analyse des emails
    
    Args:
        llm: Le modèle de langage à utiliser pour les agents
        
    Returns:
        Le graphe d'agents configuré
    """
    # Instanciation des agents
    email_scanner = EmailScannerAgent(llm)
    link_analyzer = LinkAnalyzerAgent(llm)
    nlp_analyzer = NLPAnalyzerAgent(llm)
    report_generator = ReportGeneratorAgent(llm)
    
    # Création du graphe d'état
    graph = StateGraph(EmailState)
    
    # Ajout des nœuds au graphe
    graph.add_node(WorkflowState.INITIAL_SCAN, email_scanner.analyze)
    graph.add_node(WorkflowState.ANALYZE_LINKS, link_analyzer.analyze_links)
    graph.add_node(WorkflowState.ANALYZE_ATTACHMENTS, link_analyzer.analyze_attachments)
    graph.add_node(WorkflowState.ANALYZE_LANGUAGE, nlp_analyzer.analyze)
    graph.add_node(WorkflowState.GENERATE_REPORT, report_generator.generate)
    
    # Fonction de routage après l'analyse initiale
    def route_after_initial_scan(state: EmailState) -> List[str]:
        """Détermine les prochaines étapes après l'analyse initiale"""
        logger.debug("Décision de routage après l'analyse initiale")
        next_steps = []
        
        # Vérifier si nous avons besoin d'analyser les liens
        if state.email.get("links") and not state.links_analyzed:
            logger.debug("Ajout de l'analyse des liens au flux")
            next_steps.append(WorkflowState.ANALYZE_LINKS)
            
        # Vérifier si nous avons besoin d'analyser les pièces jointes
        if state.email.get("has_attachments", False) and not state.attachments_analyzed:
            logger.debug("Ajout de l'analyse des pièces jointes au flux")
            next_steps.append(WorkflowState.ANALYZE_ATTACHMENTS)
            
        # Ajouter l'analyse du langage
        if not state.language_analyzed:
            logger.debug("Ajout de l'analyse du langage au flux")
            next_steps.append(WorkflowState.ANALYZE_LANGUAGE)
            
        # Si toutes les analyses nécessaires sont déjà effectuées ou s'il n'y a pas d'analyse supplémentaire à faire
        if not next_steps:
            logger.debug("Aucune analyse supplémentaire nécessaire, passage à la génération du rapport")
            next_steps.append(WorkflowState.GENERATE_REPORT)
            
        logger.info(f"Prochaines étapes après l'analyse initiale: {next_steps}")
        return next_steps
    
    # Fonction pour vérifier si toutes les analyses requises sont terminées
    def check_analyses_complete(state: EmailState) -> Optional[str]:
        """Vérifie si toutes les analyses requises sont terminées"""
        # Déterminer quelles analyses sont nécessaires
        needs_link_analysis = bool(state.email.get("links"))
        needs_attachment_analysis = state.email.get("has_attachments", False)
        
        # Vérifier si toutes les analyses nécessaires sont terminées
        all_analyses_complete = (
            (not needs_link_analysis or state.links_analyzed) and 
            (not needs_attachment_analysis or state.attachments_analyzed) and 
            state.language_analyzed
        )
        
        logger.debug(f"État des analyses - Liens: {state.links_analyzed if needs_link_analysis else 'N/A'}, " +
                     f"Pièces jointes: {state.attachments_analyzed if needs_attachment_analysis else 'N/A'}, " +
                     f"Langage: {state.language_analyzed}")
        
        if all_analyses_complete:
            logger.info("Toutes les analyses requises sont terminées, passage à la génération du rapport")
            return WorkflowState.GENERATE_REPORT
        
        # Sinon, rester dans l'état actuel
        logger.debug("Certaines analyses ne sont pas encore terminées")
        return None
    
    # Fonction de routage après l'analyse des liens
    def route_after_link_analysis(state: EmailState) -> List[str]:
        """Détermine les prochaines étapes après l'analyse des liens"""
        next_step = check_analyses_complete(state)
        return [next_step] if next_step else []
    
    # Fonction de routage après l'analyse des pièces jointes
    def route_after_attachment_analysis(state: EmailState) -> List[str]:
        """Détermine les prochaines étapes après l'analyse des pièces jointes"""
        next_step = check_analyses_complete(state)
        return [next_step] if next_step else []
    
    # Fonction de routage après l'analyse du langage
    def route_after_language_analysis(state: EmailState) -> List[str]:
        """Détermine les prochaines étapes après l'analyse du langage"""
        next_step = check_analyses_complete(state)
        return [next_step] if next_step else []
    
    # Fonction de décision finale
    def final_decision(state: EmailState) -> str:
        """Décide du statut final en fonction du score de menace global"""
        logger.info(f"Décision finale - Score de menace global: {state.overall_threat_score}")
        
        if state.overall_threat_score >= 0.7:
            logger.warning(f"Email classé comme CRITIQUE avec un score de {state.overall_threat_score}")
            return WorkflowState.CRITICAL
        elif state.overall_threat_score >= 0.3:
            logger.warning(f"Email classé comme SUSPECT avec un score de {state.overall_threat_score}")
            return WorkflowState.SUSPICIOUS
        else:
            logger.info(f"Email classé comme SÛR avec un score de {state.overall_threat_score}")
            return WorkflowState.SAFE
    
    # Configuration des transitions du graphe
    
    # Point de départ -> Analyse initiale
    graph.add_edge(START, WorkflowState.INITIAL_SCAN)
    
    # Après l'analyse initiale, router vers les analyses spécifiques
    graph.add_conditional_edges(
        WorkflowState.INITIAL_SCAN,
        route_after_initial_scan
    )
    
    # Après l'analyse des liens, vérifier si toutes les analyses sont terminées
    graph.add_conditional_edges(
        WorkflowState.ANALYZE_LINKS,
        route_after_link_analysis
    )
    
    # Après l'analyse des pièces jointes, vérifier si toutes les analyses sont terminées
    graph.add_conditional_edges(
        WorkflowState.ANALYZE_ATTACHMENTS,
        route_after_attachment_analysis
    )
    
    # Après l'analyse du langage, vérifier si toutes les analyses sont terminées
    graph.add_conditional_edges(
        WorkflowState.ANALYZE_LANGUAGE,
        route_after_language_analysis
    )
    
    # Après la génération du rapport, décider du statut final
    graph.add_conditional_edges(
        WorkflowState.GENERATE_REPORT,
        lambda state: [final_decision(state)]
    )
    
    # Les états finaux mènent à la fin du graphe
    graph.add_edge(WorkflowState.SAFE, END)
    graph.add_edge(WorkflowState.SUSPICIOUS, END)
    graph.add_edge(WorkflowState.CRITICAL, END)
    
    # Création du sauvegardeur de points de contrôle
    # memory = MemorySaver()
    
    # Compilation du graphe avec sauvegarde des états
    compiled_graph = graph.compile(checkpointer=memory)
    
    logger.info("Graphe d'agents créé et compilé avec succès")
    return compiled_graph


# Fonction utilitaire pour visualiser le graphe (utilisée en développement)
def visualize_graph():
    """
    Crée une visualisation du graphe d'agents (nécessite Graphviz)
    
    Note: Cette fonction est utilisée uniquement en développement.
    Pour l'utiliser, installez Graphviz et pydot:
    pip install pydot graphviz
    """
    try:
        from langgraph.visualize import visualize
        import pydot
        import tempfile
        import os
        
        # Création d'un graphe temporaire pour la visualisation
        from langchain_openai import ChatOpenAI
        dummy_llm = ChatOpenAI(temperature=0)
        graph = create_agent_graph(dummy_llm)
        
        # Génération du graphe
        dot_graph = visualize(graph)
        
        # Sauvegarde au format PNG
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            graph_viz = pydot.graph_from_dot_data(dot_graph)[0]
            graph_viz.write_png(f.name)
            print(f"Graphe sauvegardé dans {f.name}")
            
        return f"Graphe sauvegardé: {f.name}"
    except ImportError:
        return "Impossible de générer la visualisation. Installez pydot et graphviz: pip install pydot graphviz"
    except Exception as e:
        return f"Erreur lors de la génération de la visualisation: {str(e)}"


if __name__ == "__main__":
    # Configuration du logging pour les tests
    logging.basicConfig(level=logging.INFO)
    
    # Test de visualisation du graphe
    visualize_result = visualize_graph()
    print(visualize_result)
