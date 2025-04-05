# A installer : pip install --upgrade google-auth google-auth-oauthlib google-api-python-client beautifulsoup4

import os
import time
import base64
import re
import locale
from bs4 import BeautifulSoup
from email.utils import parsedate_to_datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
ATTACHMENT_DIR = 'attachments'
os.makedirs(ATTACHMENT_DIR, exist_ok=True)

# 🇫🇷 Format de date en français
try:
    locale.setlocale(locale.LC_TIME, 'fr_FR.UTF-8')
except locale.Error:
    try:
        locale.setlocale(locale.LC_TIME, 'French_France.1252')  # Windows fallback
    except:
        print("⚠️ Locale not set to French. Dates may appear in English.")

def authenticate():
    """OAuth2 login & Gmail API service setup."""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def extract_email_body_and_links(payload):
    """Extract plain text body and capture hyperlinks."""
    body_text = "(No body found)"
    links = []

    if payload.get('mimeType') == 'text/plain' and 'data' in payload.get('body', {}):
        body_text = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
        links = re.findall(r'(https?://[^\s]+)', body_text)

    elif payload.get('mimeType') == 'text/html' and 'data' in payload.get('body', {}):
        html = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
        soup = BeautifulSoup(html, 'html.parser')
        body_text = soup.get_text()
        links = [a['href'] for a in soup.find_all('a', href=True)]

    elif payload.get('mimeType', '').startswith('multipart/'):
        for part in payload.get('parts', []):
            body_text, links = extract_email_body_and_links(part)
            if body_text and body_text.strip():
                return body_text, links

    return body_text, links

def download_attachment(service, msg_id, payload):
    """Download all attachments from email."""
    def save_file(filename, file_data):
        filepath = os.path.join(ATTACHMENT_DIR, filename)
        with open(filepath, 'wb') as f:
            f.write(file_data)
        print(f"✅ Saved attachment: {filepath}")

    parts = payload.get('parts', [])
    for part in parts:
        filename = part.get('filename')
        body = part.get('body', {})
        data = body.get('data')
        attachment_id = body.get('attachmentId')

        if filename:
            if data:
                file_data = base64.urlsafe_b64decode(data.encode('UTF-8'))
                save_file(filename, file_data)
            elif attachment_id:
                att = service.users().messages().attachments().get(
                    userId='me', messageId=msg_id, id=attachment_id).execute()
                file_data = base64.urlsafe_b64decode(att['data'].encode('UTF-8'))
                save_file(filename, file_data)

        if 'parts' in part:
            download_attachment(service, msg_id, part)

def get_latest_inbox_email(service, last_msg_id=None):
    """Check for the latest email and return structured data only if it's new."""
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=1).execute()
    messages = results.get('messages', [])

    if not messages:
        print("⚠ No inbox emails found.")
        return last_msg_id

    message = service.users().messages().get(userId='me', id=messages[0]['id'], format='metadata').execute()
    headers = message.get('payload', {}).get('headers', [])

    # Get date and convert to friendly ID format
    raw_date = next((h['value'] for h in headers if h['name'].lower() == 'date'), None)
    if not raw_date:
        print("❌ Date header not found.")
        return last_msg_id

    dt = parsedate_to_datetime(raw_date)
    msg_id = dt.strftime("%a %#d %b %Y %H:%M") if os.name == 'nt' else dt.strftime("%a %-d %b %Y %H:%M")

    if msg_id == last_msg_id:
        return last_msg_id  # Nothing new

    # Now get full email
    msg = service.users().messages().get(userId='me', id=messages[0]['id']).execute()
    payload = msg.get('payload', {})

    # Extract headers
    subject = sender = recipient = "(unknown)"
    for header in headers:
        name = header['name'].lower()
        if name == 'subject':
            subject = header['value']
        elif name == 'from':
            sender = header['value']
        elif name == 'to':
            recipient = header['value']

    body_text, links = extract_email_body_and_links(payload)

    print("\n----------------------------------------")
    print("📥 New Email Received!")
    print("----------------------------------------")
    print(f"🆔 Message Key : {msg_id}")
    print(f"📝 Subject     : {subject}")
    print(f"👤 From        : {sender}")
    print(f"📬 To          : {recipient}")
    print(f"📅 Date        : {raw_date}\n")
    print("📄 Email Body:")
    print("----------------------------------------")
    print(body_text)
    print("\n🔗 Links Found:")
    print("----------------------------------------")
    print("\n".join(links) if links else "No links detected.")
    print("\n📎 Attachments:")
    print("----------------------------------------")
    download_attachment(service, messages[0]['id'], payload)

    return msg_id, subject, sender, recipient, raw_date, body_text, links

# Main loop
if __name__ == '__main__':
    gmail_service = authenticate()
    last_seen_id = None
    print("🔁 Gmail Inbox Monitor Started... (Ctrl+C to stop)")
    try:
        while True:
            result = get_latest_inbox_email(gmail_service, last_seen_id)

            if isinstance(result, tuple):
                last_seen_id, subject, sender, recipient, raw_date, body_text, links = result

                # 🧠 Place your AI agents call here
                # Example:
                # phishing_report = PhishDetect.analyze(body_text)
                # print("Phishing Risk:", phishing_report)

            time.sleep(2)
    except KeyboardInterrupt:
        print("\n👋 Monitor stopped by user.")