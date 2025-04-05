import os
import time
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Gmail API scope: read-only access
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
ATTACHMENT_DIR = 'attachments'
os.makedirs(ATTACHMENT_DIR, exist_ok=True)

def authenticate():
    """Authenticate via OAuth and return the Gmail API service."""
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

def extract_email_body(payload):
    """Recursively extract plain text email body."""
    if payload.get('mimeType') == 'text/plain' and 'data' in payload.get('body', {}):
        return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
    elif payload.get('mimeType', '').startswith('multipart/'):
        for part in payload.get('parts', []):
            text = extract_email_body(part)
            if text and text.strip():
                return text
    return "(No body found)"

def download_attachment(service, msg_id, payload):
    """Download all attachments from the message payload."""
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
    """Fetch and process the latest inbox email if it's new."""
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=1).execute()
    messages = results.get('messages', [])

    if not messages:
        print("⚠ No inbox emails found.")
        return last_msg_id

    msg_id = messages[0]['id']
    if msg_id == last_msg_id:
        return last_msg_id  # No new email

    msg = service.users().messages().get(userId='me', id=msg_id).execute()
    payload = msg.get('payload', {})
    headers = payload.get('headers', [])

    subject = sender = recipient = date = "(unknown)"
    for header in headers:
        name = header['name'].lower()
        if name == 'subject':
            subject = header['value']
        elif name == 'from':
            sender = header['value']
        elif name == 'to':
            recipient = header['value']
        elif name == 'date':
            date = header['value']

    body = extract_email_body(payload)

    # Print email info
    print("\n----------------------------------------")
    print("📥 New Email Received!")
    print("----------------------------------------")
    print(f"🆔 Message ID: {msg_id}")
    print(f"📝 Subject    : {subject}")
    print(f"👤 From       : {sender}")
    print(f"📬 To         : {recipient}")
    print(f"📅 Date       : {date}\n")
    print("📄 Email Body:")
    print("----------------------------------------")
    print(body)
    print("\n📎 Attachments:")
    print("----------------------------------------")
    download_attachment(service, msg_id, payload)

    return msg_id  # Update last seen ID

if __name__ == '__main__':
    gmail_service = authenticate()
    last_seen_id = None
    print("🔁 Gmail Inbox Monitor Started... (Ctrl+C to stop)")
    try:
        while True:
            last_seen_id = get_latest_inbox_email(gmail_service, last_seen_id)
            time.sleep(2)  # Wait 10 seconds before checking again
    except KeyboardInterrupt:
        print("\n👋 Monitor stopped by user.")
