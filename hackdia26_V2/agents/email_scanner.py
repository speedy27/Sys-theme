def scan_email(state):
    print("📥 Agent: Scan de l'email en cours...")
    email_id = state.get("email_id", "unknown-id")
    return {"email_content": f"Contenu analysé pour l'email {email_id}"}