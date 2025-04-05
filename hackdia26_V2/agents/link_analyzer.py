import requests
import base64
import time

# === CONFIGURATION CLÉS API ===
VT_API_KEY = "44f476f9d7fa7bc5e17fd3d684daf305433690539cc8ef695079a611db891de0"
URLSCAN_API_KEY = "0196069f-be55-752a-a032-f1f368c3ea4d"

# === FONCTION 1 : Analyse VirusTotal ===
def analyser_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    submit_url = "https://www.virustotal.com/api/v3/urls"
    report_url_base = "https://www.virustotal.com/api/v3/urls/"

    # Soumission
    response = requests.post(submit_url, headers=headers, data={"url": url})
    if response.status_code != 200:
        print("❌ VirusTotal - erreur de soumission :", response.text)
        return None

    print("✅ VirusTotal : soumission OK, attente...")
    time.sleep(10)

    # Récupération
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    report_response = requests.get(f"{report_url_base}{url_id}", headers=headers)
    if report_response.status_code != 200:
        print("❌ VirusTotal - erreur de rapport :", report_response.text)
        return None

    return report_response.json()["data"]["attributes"]

# === FONCTION 2 : Analyse urlscan.io ===
def analyser_url_urlscan(url):
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}

    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    if response.status_code != 200:
        print("❌ urlscan.io - erreur de soumission :", response.text)
        return None

    uuid = response.json().get("uuid")
    print(f"✅ urlscan.io : soumission OK (UUID {uuid}), attente...")
    time.sleep(10)

    result = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/")
    if result.status_code != 200:
        print("❌ urlscan.io - erreur de récupération :", result.text)
        return None

    return result.json()

# === FONCTION IA : Analyse combinée et classification ===
def evaluer_et_expliquer_risque(data_vt, data_urlscan):
    # --- Analyse VirusTotal ---
    vt_stats = data_vt.get("last_analysis_stats", {})
    vt_categories = data_vt.get("categories", {})
    vt_votes = data_vt.get("total_votes", {})
    vt_reputation = data_vt.get("reputation", 0)

    malicious = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)

    # --- Analyse urlscan.io ---
    verdict = data_urlscan.get("verdicts", {}).get("overall", {})
    urlscan_score = verdict.get("score", 0)
    urlscan_tags = verdict.get("tags", [])
    urlscan_malicious = verdict.get("malicious", False)
    title = data_urlscan.get("page", {}).get("title", "N/A")

    # === Classification simple ===
    if malicious >= 10 or urlscan_score >= 5 or urlscan_malicious:
        niveau = "❌ DANGEREUX"
    elif malicious >= 3 or suspicious >= 1 or urlscan_score >= 2 or "suspicious" in urlscan_tags:
        niveau = "⚠️ SUSPECT"
    else:
        niveau = "✅ SÛR"

    # === Génération du texte explicatif ===
    explication = f"""🔎 Analyse combinée :
- VirusTotal : {malicious} moteurs ont marqué le lien comme malicieux, {suspicious} comme suspects.
- Catégories détectées : {vt_categories if vt_categories else 'Aucune'}
- Réputation VT : {vt_reputation}, votes communauté : {vt_votes}
- urlscan.io : score = {urlscan_score}, titre de page = "{title}", tags = {urlscan_tags}
- urlscan indique malicieux : {urlscan_malicious}

🧠 Interprétation :
Le lien est classé comme **{niveau}** car les indicateurs montrent que {(
    'plusieurs moteurs antivirus et urlscan considèrent ce lien comme dangereux.'
    if niveau == "❌ DANGEREUX" else
    'certains moteurs ou le comportement du site soulèvent des soupçons.'
    if niveau == "⚠️ SUSPECT" else
    'aucun signal préoccupant majeur n’a été détecté.'
)}"""

    return niveau, explication

# === EXÉCUTION PRINCIPALE ===
if __name__ == "__main__":
    url = input("🔗 Entrez l’URL à analyser : ").strip()

    print("\n📡 Lancement de l'analyse...")

    vt_data = analyser_url_virustotal(url)
    us_data = analyser_url_urlscan(url)

    if vt_data and us_data:
        niveau, explication = evaluer_et_expliquer_risque(vt_data, us_data)
        print(f"\n🔐 Verdict final : {niveau}")
        print("📄 Justification :\n")
        print(explication)
    else:
        print("❌ Impossible de conclure : une des deux analyses a échoué.")
