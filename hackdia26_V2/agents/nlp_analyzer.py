import requests

MISTRAL_API_KEY = "OZSyUAoFi2DmsjJz5Cuqg8vWeFzG9grq"
MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"

HEADERS = {
    "Authorization": f"Bearer {MISTRAL_API_KEY}",
    "Content-Type": "application/json"
}

PROMPT_SYSTEM = """
Tu es un expert en analyse de courriers électroniques, spécialisé dans la détection de fraudes, scams et tentatives de phishing.

🎯 Objectif : Analyser le **contenu textuel** d’un e-mail et déterminer s’il contient des signes suspects.

🧠 Contexte :
- Tu détectes des tentatives de manipulation émotionnelle (urgence, menace, récompense).
- Tu repères un langage vague ou des erreurs typiques de phishing.
- Tu évalues si l’email contient une tentative d’obtenir des informations sensibles.

🔍 Ta réponse doit contenir :
1. Un résumé du contenu.
2. Un **score de suspicion** (de 0 à 10).
3. Une justification courte du score.
4. Une alerte claire si un danger est détecté.
"""

def analyze_email_body(email_body: str) -> str:
    payload = {
        "model": "mistral-medium",  # ou mistral-small, selon ton plan
        "messages": [
            {"role": "system", "content": PROMPT_SYSTEM},
            {"role": "user", "content": f"Voici le contenu de l'e-mail à analyser :\n\n{email_body}"}
        ],
        "temperature": 0.2
    }

    response = requests.post(MISTRAL_API_URL, headers=HEADERS, json=payload)
    
    if response.status_code == 200:
        return response.json()['choices'][0]['message']['content']
    else:
        return f"❌ Erreur API : {response.status_code} - {response.text}"
