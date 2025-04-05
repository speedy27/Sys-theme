def analyze_text(state):
    print("🧠 Agent: Analyse NLP en cours...")
    content = state.get("email_content", "")
    return {"nlp_result": f"Analyse sentimentale du texte : {content[:30]}..."}