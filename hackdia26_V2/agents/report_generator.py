def generate_report(state):
    print("📄 Agent: Génération du rapport final...")
    print("Contenu:", state.get("email_content"))
    print("NLP:", state.get("nlp_result"))
    print("Liens:", state.get("link_safety"))
    return {"status": "Terminé"}