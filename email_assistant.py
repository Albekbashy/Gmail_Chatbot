import os.path
import base64
import sys
from email.mime.text import MIMEText
import pandas as pd
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.compose',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

CONTACTS_FILE = 'contacts.xlsx'
CONTACTS_SHEET = 'CONTACTS_SHEET'

def get_service():
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

def list_messages(service, max_results=5):
    response = service.users().messages().list(userId='me', maxResults=max_results).execute()
    return response.get('messages', [])

def get_message_snippet(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    return msg.get('snippet')

def create_draft(service, to, subject, body):
    message = MIMEText(body, 'plain', 'utf-8')
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return service.users().drafts().create(userId='me', body={'message': {'raw': raw}}).execute()

def send_email(service, to, subject, body):
    message = MIMEText(body, 'plain', 'utf-8')
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return service.users().messages().send(userId='me', body={'raw': raw}).execute()

def get_email_from_name(name):
    df = pd.read_excel(CONTACTS_FILE, sheet_name=CONTACTS_SHEET)
    match = df[df['Nom'].str.lower() == name.lower()]
    if not match.empty:
        return match.iloc[0]['Email']
    else:
        raise ValueError(f"Nom '{name}' non trouvé dans le fichier Excel.")

def main():
    if len(sys.argv) < 3:
        print("Usage: python email_assistant.py <Nom> <Contenu> [envoyer]")
        return

    name = sys.argv[1]
    draft_body = sys.argv[2]
    send_now = False
    if len(sys.argv) >= 4 and sys.argv[3].lower() == "true":
        send_now = True

    service = get_service()

    try:
        email = get_email_from_name(name)
    except ValueError as e:
        print("Erreur :", e)
        return

    draft = create_draft(service, email, "Analyse des emails", draft_body)
    print(f"✅ Brouillon créé pour {email} (ID: {draft['id']})")

    if send_now:
        sent = send_email(service, email, "Analyse des emails", draft_body)
        print(f"✅ Email envoyé à {email} (ID: {sent['id']})")

if __name__ == '__main__':
    main()
