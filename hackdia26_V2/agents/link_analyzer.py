import requests
import base64
import time
import json

# === CLÉS API FOURNIES ===
VT_API_KEY = "44f476f9d7fa7bc5e17fd3d684daf305433690539cc8ef695079a611db891de0"
URLSCAN_API_KEY = "0196069f-be55-752a-a032-f1f368c3ea4d"
MISTRAL_API_KEY = "OZSyUAoFi2DmsjJz5Cuqg8vWeFzG9grq"

# === VIRUSTOTAL ===
def analyser_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    submit_url = "https://www.virustotal.com/api/v3/urls"
    report_url_base = "https://www.virustotal.com/api/v3/urls/"

    response = requests.post(submit_url, headers=headers, data={"url": url})
    if response.status_code != 200:
        print("❌ VirusTotal - erreur de soumission :", response.text)
        return None

    print("✅ URL soumise à VirusTotal. ⏳ Attente de l’analyse...")
    time.sleep(10)

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    report_response = requests.get(f"{report_url_base}{url_id}", headers=headers)
    if report_response.status_code != 200:
        print("❌ VirusTotal - erreur de rapport :", report_response.text)
        return None

    return report_response.json()["data"]["attributes"]

# === URLSCAN.IO ===
def analyser_url_urlscan(url):
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}

    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    if response.status_code != 200:
        print("❌ urlscan.io - erreur de soumission :", response.text)
        return None

    uuid = response.json().get("uuid")
    print(f"\n📡 Lien soumis à urlscan.io. UUID : {uuid}")
    time.sleep(10)

    result = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/")
    if result.status_code != 200:
        print("❌ urlscan.io - erreur de récupération :", result.text)
        return None

    return result.json()

# === ÉVALUATION PAR MISTRAL MEDIUM ===
def evaluer_risque_avec_mistral(data_vt, data_urlscan):
    headers = {
        "Authorization": f"Bearer {MISTRAL_API_KEY}",
        "Content-Type": "application/json"
    }
    api_url = "https://api.mistral.ai/v1/chat/completions"

    prompt = f"""
Tu es un expert en cybersécurité. Voici les résultats d’analyse de deux services.

=== Résultats VirusTotal ===
Statistiques : {data_vt.get("last_analysis_stats")}
Catégories : {data_vt.get("categories")}
Réputation : {data_vt.get("reputation")}
Votes : {data_vt.get("total_votes")}
Soumissions : {data_vt.get("times_submitted")}

=== Résultats urlscan.io ===
Page : {data_urlscan.get("page", {}).get("title")}
Score : {data_urlscan.get("verdicts", {}).get("overall", {}).get("score")}
Tags : {data_urlscan.get("verdicts", {}).get("overall", {}).get("tags")}
Malicieux : {data_urlscan.get("verdicts", {}).get("overall", {}).get("malicious")}

Donne un verdict parmi les suivants : ❌ DANGEREUX, ⚠️ SUSPECT, ✅ SÛR.
Puis explique pourquoi de façon claire.
"""

    body = {
        "model": "mistral-medium",
        "messages": [
            {"role": "system", "content": "Tu es un assistant expert en cybersécurité."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.4,
        "max_tokens": 600
    }

    response = requests.post(api_url, headers=headers, json=body)
    if response.status_code != 200:
        print("❌ Erreur Mistral :", response.text)
        return None

    return response.json()["choices"][0]["message"]["content"]

# === EXÉCUTION PRINCIPALE ===
if __name__ == "__main__":
    url = input("🔗 Entrez l’URL à analyser : ").strip()

    vt_data = analyser_url_virustotal(url)
    us_data = analyser_url_urlscan(url)

    if vt_data and us_data:
        resultat = evaluer_risque_avec_mistral(vt_data, us_data)
        print("\n🔐 Verdict final (Mistral Medium) :\n")
        print(resultat)
    else:
        print("❌ Impossible de conclure : une des deux analyses a échoué.")
