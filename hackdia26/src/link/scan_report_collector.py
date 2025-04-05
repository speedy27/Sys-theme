import requests
import time
import json
from datetime import datetime

# 🔑 Clé API
API_KEY = '0196069f-be55-752a-a032-f1f368c3ea4d'

# 🔗 URL à scanner
url = 'https://phishtank.org/phish_search.php?page=1&active=y&verified=u'

# 📤 Étape 1 : soumettre le scan
headers = {'API-Key': API_KEY, 'Content-Type': 'application/json'}
data = {"url": url, "visibility": "public"}
response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)

if response.status_code != 200:
    print("Erreur lors de la soumission :", response.text)
    exit()

uuid = response.json()["uuid"]
print(f"Lien soumis. UUID : {uuid}")
time.sleep(10)  # ⏳ Attente du scan

# 📥 Étape 2 : récupérer le résultat
result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
result_response = requests.get(result_url)

if result_response.status_code != 200:
    print("Erreur lors de la récupération :", result_response.text)
    exit()

result = result_response.json()

# 🧠 Étape 3 : extraire les infos utiles
summary = {
    "scan_uuid": uuid,
    "scan_time": result.get("task", {}).get("time"),
    "submitted_url": result.get("task", {}).get("url"),
    "final_url": result.get("page", {}).get("url"),
    "title": result.get("page", {}).get("title"),
    "domain": result.get("page", {}).get("domain"),
    "apex_domain": result.get("task", {}).get("apexDomain"),
    "ip_address": result.get("page", {}).get("ip"),
    "server": result.get("page", {}).get("server"),
    "asn_name": result.get("page", {}).get("asnname"),
    "country": result.get("page", {}).get("country"),
    "tls_issuer": result.get("page", {}).get("tlsIssuer"),
    "tls_valid_from": result.get("page", {}).get("tlsValidFrom"),
    "tls_valid_days": result.get("page", {}).get("tlsValidDays"),
    "report_url": result.get("task", {}).get("reportURL"),
    "screenshot_url": result.get("task", {}).get("screenshotURL"),
    "verdicts": result.get("verdicts", {}),
    "urls_loaded": result.get("lists", {}).get("urls", []),
    "linked_domains": result.get("lists", {}).get("linkDomains", []),
    "certificate_info": result.get("lists", {}).get("certificates", []),
    "console_messages": result.get("data", {}).get("console", []),
    "requests": result.get("data", {}).get("requests", [])
}

# 📝 Étape 4 : sauvegarder dans un fichier
#filename = f"urlscan_{uuid}.json"
#with open(filename, "w", encoding="utf-8") as f:
    #json.dump(summary, f, indent=2, ensure_ascii=False)

#rint(f"\n✅ Résumé enregistré dans : {filename}")
#print(f"Rapport : {summary['report_url']}")
#print(f"Capture : {summary['screenshot_url']}")
