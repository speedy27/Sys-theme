from langgraph.graph import StateGraph, END
from agents.email_scanner import scan_email
from agents.nlp_analyzer import analyze_text
from agents.link_analyzer import analyze_links
from agents.report_generator import generate_report

def build_graph():
    graph = StateGraph()


    graph.add_node("scan_email", scan_email)
    graph.add_node("analyze_text", analyze_text)
    graph.add_node("analyze_links", analyze_links)
    graph.add_node("generate_report", generate_report)

    graph.set_entry_point("scan_email")
    graph.add_edge("scan_email", "analyze_text")
    graph.add_edge("analyze_text", "analyze_links")
    graph.add_edge("analyze_links", "generate_report")
    graph.add_edge("generate_report", END)

    return graph.compile()