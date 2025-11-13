import json
from flask import session
import base64
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from mistral_client import query_mistral

SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.compose',
    'https://www.googleapis.com/auth/gmail.readonly'
]

class GmailAgent:
    def __init__(self, creds=None):
        self.service = build('gmail', 'v1', credentials=creds) if creds else None

    @staticmethod
    def load_credentials():
        token = session.get('google_token')
        if token:
            return Credentials.from_authorized_user_info(json.loads(token), SCOPES)
        return None

    def send_draft(self, to, subject, body):
        msg = MIMEText(body)
        msg['to'] = to
        msg['subject'] = subject
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        draft = {'message': {'raw': raw}}
        return self.service.users().drafts().create(userId='me', body=draft).execute()

    def send_existing_draft(self, draft_id):
        return self.service.users().drafts().send(userId='me', body={'id': draft_id}).execute()

    def get_email_context(self, days=7, received_only=True, max_results=3):
        after = (datetime.utcnow() - timedelta(days=days)).strftime('%Y/%m/%d')
        query = f"after:{after}"
        query += " -from:me" if received_only else " from:me"

        messages = self.service.users().messages().list(userId='me', q=query, maxResults=max_results).execute().get('messages', [])
        context = ""
        for msg in messages:
            full = self.service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = full['payload'].get('headers', [])
            from_ = next((h['value'] for h in headers if h['name'] == 'From'), 'Inconnu')
            to_ = next((h['value'] for h in headers if h['name'] == 'To'), 'Inconnu')
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'Sans objet')
            snippet = full.get('snippet', '')
            context += f"\nDe : {from_}\nÀ : {to_}\nSujet : {subject}\nMessage : {snippet}\n---\n"
        return context.strip()

    def analyze_recent_emails(self, days=7, max_results=30):
        return self._analyze_emails(" -from:me", days, max_results)

    def analyze_sent_emails(self, days=7, max_results=30):
        return self._analyze_emails(" from:me", days, max_results)

    def _analyze_emails(self, query_filter, days, max_results):
        after = (datetime.utcnow() - timedelta(days=days)).strftime('%Y/%m/%d')
        query = f"after:{after}{query_filter}"

        try:
            messages = self.service.users().messages().list(userId='me', q=query, maxResults=max_results).execute().get('messages', [])
            analysis = []

            for msg in messages:
                full = self.service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
                headers = full.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'Sans objet')
                sender_or_to = next((h['value'] for h in headers if h['name'] in ['From', 'To']), 'Inconnu')
                snippet = full.get('snippet', '')

                summary = self._safe_query_summary(snippet)
                importance = self._safe_query_importance(snippet)

                analysis.append({
                    "from" if "from" in query_filter else "to": sender_or_to,
                    "subject": subject,
                    "summary": summary,
                    "important": importance
                })

            return analysis
        except HttpError as error:
            print(f"❌ Gmail API error: {error}")
            return []

    @staticmethod
    def _safe_query_summary(snippet):
        try:
            resp = query_mistral(f"Résume ce message en une phrase simple et claire :\n\n{snippet}")
            if resp.lower().startswith('⛔'):
                return "(Résumé indisponible - limite Mistral atteinte)"
            return resp
        except Exception:
            return "(Résumé indisponible)"

    @staticmethod
    def _safe_query_importance(snippet):
        try:
            resp = query_mistral(f"Cet email est-il important pour l'utilisateur ? Réponds uniquement par 'Oui' ou 'Non' et explique brièvement pourquoi :\n\n{snippet}")
            if resp.lower().startswith('⛔'):
                return "(Importance non déterminée - limite Mistral atteinte)"
            return resp
        except Exception:
            return "(Importance non déterminée)"

    def search_emails_by_subject(self, subject_part, days=30, received_only=True, max_results=30):
        after = (datetime.utcnow() - timedelta(days=days)).strftime('%Y/%m/%d')
        query = f'after:{after} subject:"{subject_part}"'
        query += " -from:me" if received_only else ""
        try:
            messages = self.service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute().get('messages', [])
            emails = []
            for msg in messages:
                full = self.service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
                headers = full.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'Sans objet')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Inconnu')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), '')
                snippet = full.get('snippet', '')
                body = self.extract_email_body(full)
                emails.append({
                    'from': sender,
                    'subject': subject,
                    'date': date,
                    'snippet': snippet,
                    'body': body,
                })
            return emails
        except HttpError as error:
            print(f"❌ Gmail API error: {error}")
            return []

    def debug_search_emails_by_subject(self, search_term, max_results=50):
        """Enhanced Gmail search with deep debugging, multiple strategies and label logging."""
        try:
            print(f"\n🔍 DEBUG SEARCH for: '{search_term}'")

            search_queries = [
                f'subject:"{search_term}"',
                f'subject:{search_term}',
                f'"{search_term}"',
                search_term,
                f'body:"{search_term}"',
                f'in:sent {search_term}',
                f'in:anywhere {search_term}',
            ]

            all_found_emails = []
            used_query = None

            for i, query in enumerate(search_queries):
                try:
                    #print(f"\n📧 [{i+1}/{len(search_queries)}] Trying search: '{query}'")
                    results = self.service.users().messages().list(
                        userId='me',
                        q=query,
                        maxResults=max_results
                    ).execute()
                    messages = results.get('messages', [])
                    #print(f"   → Found {len(messages)} message(s) with this query.")

                    for msg in messages:
                        try:
                            email_data = self.service.users().messages().get(
                                userId='me',
                                id=msg['id'],
                                format='full'
                            ).execute()
                            headers = email_data['payload'].get('headers', [])
                            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                            from_email = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                            date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
                            label_ids = email_data.get('labelIds', [])
                            snippet = email_data.get('snippet', '')

                            body = self.extract_email_body(email_data)
                            found_in_subject = search_term.lower() in subject.lower()
                            found_in_body = body and search_term.lower() in body.lower()

                            if found_in_subject:
                                print(f"   ✅ Search term found in SUBJECT")
                            if found_in_body:
                                print(f"   ✅ Search term found in BODY")

                            all_found_emails.append({
                                'id': msg['id'],
                                'subject': subject,
                                'from': from_email,
                                'date': date,
                                'body': body or snippet,
                                'labels': label_ids,
                                'query_used': query
                            })
                        except Exception as e:
                            print(f"   ❌ Error fetching message: {e}")
                            continue

                    if messages:
                        used_query = query
                        break
                except Exception as e:
                    print(f"   ❌ Error with query '{query}': {e}")
                    continue

            unique_emails = []
            seen_ids = set()
            for email in all_found_emails:
                if email['id'] not in seen_ids:
                    unique_emails.append(email)
                    seen_ids.add(email['id'])

            recent_results = self.service.users().messages().list(
                userId='me', maxResults=20).execute()
            recent_messages = recent_results.get('messages', [])
            for i, msg in enumerate(recent_messages):
                try:
                    email_data = self.service.users().messages().get(
                        userId='me',
                        id=msg['id'],
                        format='full'
                    ).execute()
                    headers = email_data['payload'].get('headers', [])
                    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
                    snippet = email_data.get('snippet', '')
                    print(f"  [{i+1}] {subject[:60]} / {snippet[:40]}...")
                except Exception:
                    continue

            return unique_emails

        except Exception as e:
            print(f"❌ Debug search failed: {e}")
            return []

    def extract_email_body(self, full):
        """Extract the plain text body from the Gmail API full message."""
        payload = full.get('payload', {})
        if payload.get('mimeType', '') == 'text/plain':
            data = payload.get('body', {}).get('data', '')
            return base64.urlsafe_b64decode(data.encode()).decode('utf-8', errors='ignore') if data else ''
        else:
            parts = payload.get('parts', [])
            for part in parts:
                if part.get('mimeType') == 'text/plain':
                    data = part.get('body', {}).get('data', '')
                    return base64.urlsafe_b64decode(data.encode()).decode('utf-8', errors='ignore') if data else ''
        return ''  
    