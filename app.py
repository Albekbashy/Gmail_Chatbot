from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, render_template_string
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import json
import os
import re
import pandas as pd
from gmail_agent import GmailAgent
from email.mime.text import MIMEText
from dotenv import load_dotenv
import base64
from mistral_client import query_mistral
from difflib import get_close_matches
import unicodedata

SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.compose',
    'https://www.googleapis.com/auth/gmail.readonly'
]

load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret_key_change_this_in_production")

app.config['SESSION_COOKIE_NAME'] = 'gmail_session'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

def get_redirect_uri():
    return "http://localhost:5003/oauth2callback"

@app.route("/auth")
def auth():
    redirect_uri = get_redirect_uri()
    print("REDIRECT_URI used for auth:", redirect_uri)

    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    auth_url, _ = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='select_account consent'
    )
    print("AUTH_URL generated:", auth_url)
    return redirect(auth_url)

@app.route("/oauth2callback", methods=['GET', 'POST'])
def oauth2callback():
    try:
        print("=== DEBUG OAUTH CALLBACK ===")
        print("Full request.url:", request.url)
        print("Request args dict:", dict(request.args))
        print("===============================")

        if session.get('google_token'):
            if request.method == "POST":
                return jsonify({'success': True})
            else:
                return render_template_string("""
                  <h2>✅ Already authenticated! Redirecting...</h2>
                  <script>setTimeout(function(){window.location.href = '/gmail';}, 200);</script>
                """)

        code = None
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            code = data.get('code')
        if not code:
            code = request.args.get('code')

        if not code:
            return render_template_string("""
                <h2>OAuth Authorization Required</h2>
                <p>Please complete the OAuth flow:</p>
                <ol>
                    <li><a href="{{ auth_url }}" target="_blank">Click here to authorize</a></li>
                    <li>After authorization, you will be redirected and the token will be saved.</li>
                </ol>
                <script>
                    if (window.location.search.includes('code=')) {
                        const urlParams = new URLSearchParams(window.location.search);
                        const code = urlParams.get('code');
                        if (code) {
                            fetch('/oauth2callback', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({code: code})
                            }).then(response => {
                                window.location.href = '/gmail';
                            });
                        }
                    }
                </script>
            """, auth_url=url_for('auth', _external=True))

        redirect_uri = get_redirect_uri()
        flow = Flow.from_client_secrets_file(
            'credentials.json',
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        flow.fetch_token(code=code)
        creds = flow.credentials
        session['google_token'] = creds.to_json()

        if request.method == "POST":
            return jsonify({'success': True})
        else:
            return render_template_string("""
              <html>
                <body style="background:#181A24; color:#fff; padding:40px;font-family:sans-serif">
                  <h2>✅ Authentication successful!</h2>
                  <p>Redirecting to Gmail tool...</p>
                  <script>
                    setTimeout(function() {
                      window.location.href = '/gmail';
                    }, 400);
                  </script>
                </body>
              </html>
            """)

    except Exception as e:
        print("OAUTH2CALLBACK EXCEPTION:", repr(e))
        import traceback
        return render_template_string(
            "<h2 style='color:red'>Internal error: {{msg}}</h2><pre>{{trace}}</pre>",
            msg=str(e),
            trace=traceback.format_exc()
        ), 500


def fuzzy_find(term, vocab, cutoff=0.7):
    matches = get_close_matches(term, vocab, n=1, cutoff=cutoff)
    return matches[0] if matches else None

def normalize_command(prompt):
    commands = ['draft', 'send', 'sent', 'received', 'reçus', 'email', 'mail', 'write', 'écris', 'rédige', 'envoyer', 'envoie', 'compose']
    words = re.findall(r'\w+', prompt.lower())
    found = []
    for word in words:
        match = fuzzy_find(word, commands)
        if match:
            found.append(match)
    return set(found)

def is_fuzzy_match(word, keywords, cutoff=0.7):
    return bool(get_close_matches(word, keywords, n=1, cutoff=cutoff))

def load_data_from_csv():
    raw_url = os.getenv("CSV_FILE_PATH", "").strip()
    if not raw_url:
        print("❌ No CSV link configured via CSV_FILE_PATH.")
        return pd.DataFrame()
    if "docs.google.com/spreadsheets" in raw_url:
        m_id = re.search(r"/d/([a-zA-Z0-9_-]+)", raw_url)
        m_gid = re.search(r"[?&]gid=(\d+)", raw_url)
        sheet_id = m_id.group(1) if m_id else None
        gid = m_gid.group(1) if m_gid else "0"
        if sheet_id:
            csv_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}"
        else:
            print("❌ Unable to extract sheet ID from CSV_FILE_PATH.")
            return pd.DataFrame()
    else:
        csv_url = raw_url
    try:
        df = pd.read_csv(csv_url, dtype=str, engine="python", sep=None, on_bad_lines="warn")
        df = df.map(lambda x: x.strip() if isinstance(x, str) else x)
        print(f"✅ {len(df)} rows loaded from {csv_url}")
        return df
    except Exception as e:
        print(f"❌ Error loading CSV: {e}")
        return pd.DataFrame()

def get_email_from_name(name):
    df = load_data_from_csv()
    match = df[df['Nom'].str.strip().str.lower() == name.strip().lower()]
    if not match.empty:
        return match.iloc[0]['Email']
    else:
        raise ValueError(f"Name '{name}' not found in contacts.")

def resolve_to_contact_email(value):
    try:
        return get_email_from_name(value)
    except Exception:
        pass
    if '@' in value:
        df = load_data_from_csv()
        emails = df['Email'].astype(str).str.strip().str.lower()
        if value.strip().lower() in emails.values:
            return value
        left = value.split('@')[0]
        try:
            return get_email_from_name(left)
        except Exception:
            pass
    raise ValueError(f"Unable to find email for {value}")

def send_email(service, to, subject, body):
    """Actually SEND an email (not draft)"""
    msg = MIMEText(body)
    msg['to'] = to
    msg['subject'] = subject
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    return service.users().messages().send(userId='me', body={'raw': raw}).execute()

def get_memory():
    return session.get("chat_history", [])
    
def update_memory(role, content):
    history = session.get("chat_history", [])
    history.append({"role": role, "content": content})
    if len(history) > 6:
        history = history[-6:]
    session["chat_history"] = history
    
def markdown_bold_to_html(text):
    return re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)

def format_paragraphs(text):
    paras = re.split(r"\n\s*\n|\r\n\r\n", text.strip())
    html = ""
    for para in paras:
        if para.strip():
            html += f"<p style='margin-bottom:24px; color:#fff;'>{markdown_bold_to_html(para.strip().replace(chr(10), '<br>'))}</p>"
    return html

def format_email_response(action_type, email, subject, body, status_message=None):
    body_html = format_paragraphs(body)
    titre = "✉ <span style='color:#ffa82c;'>Email sent successfully</span>" if action_type == "send" else "✉ <span style='color:#ffa82c;'>Draft saved successfully</span>"
    statut = status_message or ("Your email has been sent successfully." if action_type == "send" else "Your draft has been saved and is ready to be sent.")
    return f"""
    <div class="mail-confirm-block" style="background:rgba(255,255,255,0.13);padding:18px 22px;border-radius:16px;margin:12px 0;border:2px solid #ffa82c;box-shadow:0 2px 8px rgba(0,0,0,0.09);color:#fff;">
      <h3 style="margin-bottom:10px;">{titre}</h3>
      <div style="margin-bottom:10px;"><b>Recipient:</b> {email}<br>
         <b>Subject:</b> {subject}</div>
      <hr style="border:0;border-top:1px solid #eee;margin: 16px 0 16px 0;">
      <div style="font-weight:bold;margin-bottom:8px;color:#ffa82c;">📄 Message Content</div>
      <div style="background:rgba(255,255,255,0.17);padding:15px 20px;border-radius:12px;border-left:4px solid #ffa82c;margin-bottom:18px;font-size:16px;color:#fff;">
        {body_html}
      </div>
      <div style="font-weight:bold;margin-top:4px;"><span style='color:#ffa82c;'>Status:</span> 📝 {statut}</div>
    </div>
    """

def format_analysis_result(result):
    html = """
    <div class="mail-confirm-block" style="background:rgba(255,255,255,0.13);padding:18px 22px;border-radius:16px;margin:12px 0;border:2px solid #ffa82c;box-shadow:0 2px 8px rgba(0,0,0,0.09);color:#fff;max-height:420px;overflow-y:auto;">
        <div style="font-size:21px;color:#ffa82c;font-weight:bold;display:flex;align-items:center;margin-bottom:16px;">
            <span style="font-size:24px;margin-right:10px;">📬</span>Email Analysis
        </div>
    """
    for item in result:
        html += f"""
        <div style='background:rgba(255,255,255,0.17);padding:13px 18px;border-radius:12px;border-left:4px solid #ffa82c;margin-bottom:22px;font-size:15px;color:#fff;'>
            <div style='margin-bottom:4px'><b>From:</b> {markdown_bold_to_html(item.get('from', ''))}</div>
            <div style='margin-bottom:4px'><b>Subject:</b> {markdown_bold_to_html(item.get('subject', ''))}</div>
            <div style='margin-bottom:10px;'><b>Summary:</b> <span style='background:rgba(255,255,255,0.25);padding:6px 10px 6px 10px;display:inline-block;border-radius:8px;margin-left:2px;color:#fff;'>{markdown_bold_to_html(item.get('summary', ''))}</span></div>
            <div style='margin-bottom:2px'><b>Important?</b> {markdown_bold_to_html(item.get('important', ''))}</div>
        </div>
        """
    html += "</div>"
    return html

def format_analysis_from_llm(llm_response):
    mail_blocks = re.split(r'(?=(?:De\s*:|De :))', llm_response)
    count_valid = 0
    html = '''
    <div class="mail-confirm-block" style="background:rgba(255,255,255,0.13);padding:18px 22px;border-radius:16px;margin:12px 0 12px 0;border:2px solid #ffa82c;box-shadow:0 2px 8px rgba(0,0,0,0.09);color:#fff;max-height:440px;overflow-y:auto;">
        <div style="font-size:21px;color:#ffa82c;font-weight:bold;display:flex;align-items:center;margin-bottom:16px;">
            <span style="font-size:24px;margin-right:10px;">📬</span>Email Analysis
        </div>
    '''
    for block in mail_blocks:
        de = re.search(r'De\s*:\s*(.+)', block)
        objet = re.search(r'Objet\s*:\s*(.+)', block)
        resume = re.search(r'Résumé\s*:\s*(.+)', block)
        important = re.search(r'Important\s*\??\s*:?(.+)', block)
        if (de and (objet or resume or important)):
            count_valid += 1
            html += "<div style='background:rgba(255,255,255,0.17);padding:13px 18px;border-radius:12px;border-left:4px solid #ffa82c;margin-bottom:22px;font-size:15px;color:#fff;'>"
            html += f"<div style='margin-bottom:4px'><b>From:</b> {markdown_bold_to_html(de.group(1).strip())}</div>"
            if objet:    html += f"<div style='margin-bottom:4px'><b>Subject:</b> {markdown_bold_to_html(objet.group(1).strip())}</div>"
            if resume:   html += f"<div style='margin-bottom:10px;'><b>Summary:</b> <span style='background:rgba(255,255,255,0.25);padding:6px 10px 6px 10px;display:inline-block;border-radius:8px;margin-left:2px;color:#fff;'>{markdown_bold_to_html(resume.group(1).strip())}</span></div>"
            if important:html += f"<div style='margin-bottom:2px'><b>Important?</b> {markdown_bold_to_html(important.group(1).strip())}</div>"
            html += "</div>"
    if count_valid == 0:
        html += "<div style='margin: 20px 0;'>No data to display.</div>"
    html += "</div>"
    return html

def format_synthese_to_bullets(reply):
    reply = markdown_bold_to_html(reply)
    bullets = re.findall(r'\d+\.\s*([^\n]+(?:\n(?!\d+\.).+)*)', reply, re.DOTALL)
    seen = set()
    html = '''
    <div class="mail-confirm-block" style="background:rgba(255,255,255,0.13);padding:18px 22px;border-radius:16px;margin:12px 0;border:2px solid #ffa82c;box-shadow:0 2px 8px rgba(0,0,0,0.09);color:#fff;">
        <div style="font-size:21px;color:#ffa82c;font-weight:bold;display:flex;align-items:center;margin-bottom:10px;">
            <span style="font-size:23px;margin-right:10px;">📑</span>Summary
        </div>
        <div style="margin-bottom:10px;color:#fff;">Here is a summary of your recent emails:</div>
        <ol style="margin-left:24px;margin-bottom:10px;color:#fff;">
    '''
    for b in bullets:
        txt = b.strip()
        if txt and txt not in seen:
            html += f'<li style="margin-bottom:17px;color:#fff;">{markdown_bold_to_html(txt.replace(chr(10), "<br>"))}</li>'
            seen.add(txt)
    if not bullets:
        html += f'<li style="margin-bottom:17px;color:#fff;">{markdown_bold_to_html(reply.replace(chr(10), "<br>"))}</li>'
    html += '</ol></div>'
    return html

def extract_subject_search(prompt):
    patterns = [
        r'(?:title|subject|sujet)\s+(?:contains|contient|contiennent)\s+[\'"]?(.+?)[\'"]?(?:\s|$)',
        r'(?:whose|dont le|où le)\s*(?:title|subject|sujet)\s*(?:contains|contient|contiennent)\s+[\'"]?(.+?)[\'"]?(?:\s|$)',
        r'(?:emails|mails|messages)\s*(?:avec|with)?\s*(?:title|subject|sujet)\s*(?:containing|contenant|contenant)\s+[\'"]?(.+?)[\'"]?(?:\s|$)',
    ]
    prompt_norm = unicodedata.normalize("NFKD", prompt.lower())
    for pat in patterns:
        m = re.search(pat, prompt_norm, re.IGNORECASE)
        if m:
            return m.group(1).strip(' "\'')
    m = re.search(r'contient\s+(.+?)(?:\s|$)', prompt_norm, re.IGNORECASE)
    if m:
        return m.group(1).strip(' "\'')
    return None

def is_email_summary_request(prompt):
    patterns = [
        r"(synthétise|récapitule|résume|summary|synthese|synthèse).*(?:email|mail|message)",
        r"summarize.*(?:email|mail|message)",
    ]
    prompt_lc = prompt.lower()
    for pat in patterns:
        if re.search(pat, prompt_lc):
            return True
    return False

@app.route("/chat", methods=["POST"])
def chat():
    print("=== /chat CALLED ===")
    print("Session:", dict(session))
    google_token_raw = session.get('google_token')

    if not google_token_raw:
        print("❌ google_token not found in session, unauthorized.")
        return jsonify({"error": "Gmail not authenticated. Please login again."}), 401
    
    gmail = None
    try:
        creds_info = json.loads(google_token_raw)
        print("Loaded creds_info:", creds_info)
        creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
        print("Credentials loaded:", creds)
        gmail = GmailAgent(creds=creds)
    except Exception as e:
        print("❌ Exception when loading credentials from session:", e)
        return jsonify({"error": f"Gmail not available: {e}"}), 500
    
    prompt = request.json.get("prompt", "")
    if not prompt:
        return jsonify({"error": "Missing prompt"}), 400
    if not gmail:
        return jsonify({"error": "Gmail not available"}), 500
    
    subject_search = extract_subject_search(prompt)
    search_term = subject_search or prompt

    # Email summary by subject request
    if is_email_summary_request(prompt) or subject_search:
        emails = gmail.debug_search_emails_by_subject(search_term, max_results=50)
        if not emails:
            return jsonify({"response": f"No emails found for: <b>{search_term}</b>."})

        all_texts = ""
        for mail in emails:
            all_texts += f"\n---\nFROM: {mail['from']}\nSUBJECT: {mail['subject']}\nDATE: {mail['date']}\n{mail['body'] or mail.get('snippet', '')}\n"
        
        llm_prompt = f"""
You are a professional email assistant.
Generate a comprehensive summary of the following emails in HTML format.

Structure your summary as:
<div class="email-summary">
<div class="summary-header"><b>Email Thread Summary</b></div>
<b>Topic:</b> [main topic]<br>
<b>Participants:</b>
<ul>
<li>[Name] ([email])</li>
</ul>
<b>Timeline:</b>
<ul>
<li><b>[date]</b>: [event/action]</li>
</ul>
<b>Key Points:</b>
<ul>
<li>[Important point 1]</li>
<li>[Important point 2]</li>
</ul>
<b>Action Items:</b>
<ul>
<li>[Action needed, if any]</li>
</ul>
</div>

Instructions:
- Use HTML tags (no markdown)
- Labels (Topic, Participants, etc.) must be in <b>bold</b>
- Be concise but comprehensive
- Respond ONLY with the HTML block

Emails to summarize:
{all_texts}
"""
        try:
            reply = query_mistral(llm_prompt)
        except Exception as e:
            return jsonify({"error": f"AI error: {str(e)}"}), 500

        reply = markdown_bold_to_html(reply.strip())
        html = f"""
        <div class="mail-confirm-block" style="background:rgba(255,255,255,0.13);padding:18px 22px;border-radius:16px;margin:12px 0;border:2px solid #ffa82c;box-shadow:0 2px 8px rgba(0,0,0,0.09);color:#fff;max-width:780px;">
        <div style="font-size:21px;color:#ffa82c;font-weight:bold;display:flex;align-items:center;margin-bottom:14px;">
            <span style="font-size:25px;margin-right:10px;">📑</span>Email Summary
        </div>
        <div style="white-space:pre-line;">{reply}</div>
        </div>
        """
        update_memory("assistant", html)
        return jsonify({"response": html})

    memory = get_memory()
    update_memory("user", prompt)

    # Check if user wants to SEND or DRAFT
    send_keywords = ['send', 'envoyer', 'envoie', 'envoi', 'sent']
    draft_keywords = ['draft', 'brouillon', 'save', 'sauvegarder']
    
    prompt_lower = prompt.lower()
    wants_to_send = any(word in prompt_lower for word in send_keywords)
    wants_to_draft = any(word in prompt_lower for word in draft_keywords)
    
    action_type = "send" if wants_to_send else ("draft" if wants_to_draft else "send")
    
    print(f"🔍 User wants to: {action_type}")

    action_intents = {'draft', 'send', 'sent', 'write', 'écris', 'rédige', 'compose', 'envoyer', 'envoie'}
    analyze_intents = {'analyze', 'analyse', 'résume', 'summary', 'montre', 'affiche', 'list', 'liste', 'voir', 'montrez'}
    user_words = set(re.findall(r'\w+', prompt.lower()))
    must_force_action = bool(action_intents & user_words) and not bool(analyze_intents & user_words)

    analyze_keywords = ['analyze', 'analyse', 'analysez', 'analize', 'analayze', 'analyser', 'analyse', 'analiser', 'analisez']
    synthese_keywords = ['synthese', 'synthèse', 'synthes', 'summary', 'résumé', 'resumé', 'synteze', 'synthesys', 'synthesise']
    prompt_words = re.findall(r'\w+', prompt.lower())
    found_analyze = any(is_fuzzy_match(w, analyze_keywords, 0.7) for w in prompt_words)
    found_synthese = any(is_fuzzy_match(w, synthese_keywords, 0.7) for w in prompt_words)

    days = 7
    received_only = True
    match = re.search(r"last\s+(\d+)\s+(days?|weeks?|months?)|past\s+(\d+)\s+(days?|weeks?|months?)", prompt.lower())
    if match:
        num = int(match.group(1) or match.group(4))
        unit = (match.group(2) or match.group(5)).lower()
        days = num * 30 if "month" in unit else num * 7 if "week" in unit else num

    context = gmail.get_email_context(days=days, received_only=received_only, max_results=3)
    memory_str = "\n".join(
        f"{m['role'].capitalize()}: {m['content']}" for m in memory[-5:]
    )
    
    final_prompt = f"""
You are a professional email assistant.
You MUST respond in FRENCH unless explicitly asked for English.

CRITICAL: When the user wants to send or draft an email, you MUST respond with EXACTLY this format:
[ACTION: send to recipient@email.com with subject "Subject Here" and body "Body text here"]
OR
[ACTION: draft to recipient@email.com with subject "Subject Here" and body "Body text here"]

User's last 3 emails for context:
{context}

Recent conversation:
{memory_str}

Current request: {prompt}

If this is an email request, respond with the [ACTION: ...] block.
Create a professional, contextually appropriate message in French that addresses the user's request.
"""

    try:
        llm_failed = False
        reply = ""
        
        try:
            reply = query_mistral(final_prompt)
            print(f"✅ AI response: {reply[:200]}...")
            
            if "⛔" in reply or "Erreur" in reply or "401" in reply:
                print("⚠️ AI API error detected in response")
                llm_failed = True
        except Exception as e:
            print(f"❌ AI exception: {e}")
            llm_failed = True
        
        if llm_failed and must_force_action:
            print("🔧 AI failed, creating email directly from user request")
            
            name_match = re.search(r'\b(?:to|à|pour)\s+(\w+)', prompt, re.IGNORECASE)
            recipient_name = name_match.group(1) if name_match else "recipient"
            
            # Extract the actual message content from the prompt - FIXED VERSION
            message_content = None
            
            # Pattern 1: "tell/say to NAME (that) MESSAGE"
            pattern1 = re.search(r'(?:tell|say to|inform|dire à|dis à|prévenir)\s+(?:him|her|them|le|la|les|lui|\w+)\s+(?:that|de|que)?\s*(.+)', prompt, re.IGNORECASE)
            if pattern1:
                message_content = pattern1.group(1).strip()
            
            # Pattern 2: "and tell him MESSAGE"
            if not message_content or len(message_content) < 5:
                pattern2 = re.search(r'(?:and|et)\s+(?:tell|say|inform|dis|préviens?)\s+(?:him|her|them|le|la|les|lui)\s+(?:that|de|que)?\s*(.+)', prompt, re.IGNORECASE)
                if pattern2:
                    message_content = pattern2.group(1).strip()
            
            # Pattern 3: Just look for "and MESSAGE" after recipient
            if not message_content or len(message_content) < 5:
                # Find position after recipient name, then grab everything after "and"
                name_pos = prompt.lower().find(recipient_name.lower())
                if name_pos > 0:
                    after_name = prompt[name_pos + len(recipient_name):]
                    and_match = re.search(r'(?:and|et)\s+(.+)', after_name, re.IGNORECASE)
                    if and_match:
                        message_content = and_match.group(1).strip()
            
            # Clean up the message content
            if message_content:
                # Remove trailing quotes if present
                message_content = message_content.strip('"\'')
                print(f"✅ Extracted message: '{message_content}'")
            
            # Check for specific topics
            topic_match = re.search(r'(?:congratulate|félicit|congrat|success|réuss|exam)', prompt, re.IGNORECASE)
            meeting_match = re.search(r'(?:meeting|réunion|rendez-vous)', prompt, re.IGNORECASE)
            
            if topic_match:
                subject = "Félicitations ! 🎉"
                body = f"""Bonjour,

Je voulais te féliciter chaleureusement pour ta réussite ! C'est un excellent résultat et tu peux être fier de toi.

Tous mes vœux pour la suite !

Cordialement"""
            elif meeting_match and message_content:
                subject = "Réunion"
                body = f"""Bonjour,

{message_content.capitalize()}

Cordialement"""
            elif message_content:
                subject = "Message"
                body = f"""Bonjour,

{message_content.capitalize()}

Cordialement"""
            else:
                subject = "Message"
                body = """Bonjour,

J'espère que tu vas bien. N'hésite pas à me tenir au courant.

Cordialement"""
            
            try:
                email = resolve_to_contact_email(recipient_name)
                print(f"✅ Resolved {recipient_name} to {email}")
            except Exception as e:
                print(f"❌ Could not resolve email: {e}")
                return jsonify({"error": f"Unable to find email for recipient '{recipient_name}'"}), 400
            
            if action_type == "send":
                print(f"📧 SENDING email to {email}")
                send_email(gmail.service, email, subject, body)
                status_message = "Your email has been sent successfully."
            else:
                print(f"📝 DRAFTING email to {email}")
                gmail.send_draft(email, subject, body)
                status_message = "Your draft has been saved and is ready to be sent."
            
            html_block = format_email_response(action_type, email, subject, body, status_message)
            update_memory("assistant", html_block)
            return jsonify({"response": html_block})
        
        if not llm_failed:
            update_memory("assistant", reply.strip())

            action_patterns = [
                r'\[ACTION:\s*(send|draft|envoyer_email|sauvegarder_brouillon)\s+(?:to|à)\s+([^\s]+)\s+(?:with|avec)\s+subject\s+"([^"]+)"\s+(?:and|et)\s+body\s+"([^"]+)"\]',
                r'\[ACTION:\s*(send|draft|envoyer_email|sauvegarder_brouillon)\s+(?:to|à)\s+([^\s]+)\s+(?:with|avec)\s+sujet\s+"([^"]+)"\s+(?:and|et)\s+corps\s+"([^"]+)"\]',
            ]
            
            action_match = None
            for pattern in action_patterns:
                action_match = re.search(pattern, reply, re.DOTALL | re.IGNORECASE)
                if action_match:
                    break

            if action_match:
                action_verb = action_match.group(1).lower()
                if action_verb in ['send', 'envoyer_email', 'envoyer']:
                    action_type = "send"
                else:
                    action_type = "draft"
                    
                name_or_email = action_match.group(2).strip()
                subject = action_match.group(3).strip()
                body = action_match.group(4).strip()
                
                print(f"🎯 Action detected: {action_type} to {name_or_email}")
                
                try:
                    if "@" not in name_or_email:
                        name_or_email = get_email_from_name(name_or_email)
                except Exception as e:
                    return jsonify({"error": f"Error resolving email: {str(e)}"}), 400

                if action_type == "send":
                    print(f"📧 SENDING email via AI action")
                    send_email(gmail.service, name_or_email, subject, body)
                    status_message = "Your email has been sent successfully."
                else:
                    print(f"📝 DRAFTING email via AI action")
                    gmail.send_draft(name_or_email, subject, body)
                    status_message = "Your draft has been saved and is ready to be sent."

                html_block = format_email_response(action_type, name_or_email, subject, body, status_message)
                update_memory("assistant", html_block)
                return jsonify({"response": html_block})
            
            # If no action block found but user clearly wants to send/draft
            elif must_force_action:
                print("🔧 No action block found, but user wants to send/draft - extracting from prompt")
                print(f"🔍 Original prompt: {prompt}")
                
                name_search = re.search(r'\b(?:to|à|pour)\s+(\w+)', prompt, re.IGNORECASE)
                name = name_search.group(1) if name_search else "recipient"
                
                # Extract the actual message content from the prompt - IMPROVED PATTERNS
                message_content = None
                
                # Try multiple patterns in order of specificity
                patterns = [
                    # "tell him/her/them (that) MESSAGE"
                    r'(?:tell|say to|inform)\s+(?:him|her|them)\s+(?:that\s+)?(.+?)(?:\.|$)',
                    # "and tell him MESSAGE" or "et dis-lui MESSAGE"
                    r'(?:and|et)\s+(?:tell|say to|inform|dis|préviens?)\s+(?:him|her|them|le|la|les|lui)\s+(?:that\s+)?(.+?)(?:\.|$)',
                    # "tell NAME MESSAGE"
                    r'(?:tell|say to|inform|dire|informer|prévenir)\s+\w+\s+(?:that\s+)?(.+?)(?:\.|$)',
                    # Just grab everything after "and"
                    r'(?:and|et)\s+(.+?)(?:\.|$)',
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, prompt, re.IGNORECASE)
                    if match:
                        extracted = match.group(1).strip()
                        print(f"✅ Extracted content: '{extracted}'")
                        # Make sure it's substantial
                        if len(extracted) > 5 and not extracted.lower().startswith(('to ', 'à ', 'pour ')):
                            message_content = extracted
                            break
                
                print(f"📝 Final message content: {message_content}")
                
                # Check for specific topics
                topic_match = re.search(r'(?:congratulate|félicit|congrat|success|réuss|exam)', prompt, re.IGNORECASE)
                meeting_match = re.search(r'(?:meeting|réunion|rendez-vous)', prompt, re.IGNORECASE)
                
                if topic_match:
                    subject = "Félicitations ! 🎉"
                    body = """Bonjour,

Je voulais te féliciter chaleureusement pour ta réussite ! C'est un excellent résultat et tu peux être fier de toi.

Tous mes vœux pour la suite !

Cordialement"""
                elif meeting_match and message_content:
                    subject = "Réunion"
                    body = f"""Bonjour,

{message_content.capitalize()}

Cordialement"""
                elif message_content:
                    subject = "Message"
                    body = f"""Bonjour,

{message_content.capitalize()}

Cordialement"""
                else:
                    subject = "Message"
                    body = """Bonjour,

J'espère que tu vas bien. N'hésite pas à me tenir au courant.

Cordialement"""
                
                try:
                    email = resolve_to_contact_email(name)
                except Exception as e:
                    return jsonify({"error": f"Error resolving email: {str(e)}"}), 400
                
                if action_type == "send":
                    print(f"📧 SENDING email (no action block)")
                    send_email(gmail.service, email, subject, body)
                    status_message = "Your email has been sent successfully."
                else:
                    print(f"📝 DRAFTING email (no action block)")
                    gmail.send_draft(email, subject, body)
                    status_message = "Your draft has been saved and is ready to be sent."
                    
                html_block = format_email_response(action_type, email, subject, body, status_message)
                update_memory("assistant", html_block)
                return jsonify({"response": html_block})


        # Analysis: check by real results
        result = gmail.analyze_recent_emails(days=days)
        analysis_trigger = (
            (bool(analyze_intents & user_words) or found_analyze)
            or reply.lower().strip().startswith("voici les emails que vous avez reçus")
            or reply.lower().strip().startswith("voici la liste des emails")
            or reply.lower().strip().startswith("de :")
        )
        if analysis_trigger and result and isinstance(result, list) and len(result) > 0 and 'from' in result[0]:
            html = format_analysis_result(result)
            update_memory("assistant", html)
            return jsonify({"response": html})

        if analysis_trigger:
            html = format_analysis_from_llm(reply)
            update_memory("assistant", html)
            return jsonify({"response": html})

        if ("synthèse" in reply.lower() or "summary" in reply.lower() or found_synthese) \
                and not reply.strip().startswith("<div") \
                and "[ACTION:" not in reply and "Analyse des emails reçus" not in reply:
            html = format_synthese_to_bullets(reply)
            update_memory("assistant", html)
            return jsonify({"response": html})

        return jsonify({"response": reply.strip()})
        
    except Exception as e:
        print(f"❌ Chat error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Error: {str(e)}"}), 500

@app.route('/memory', methods=['GET'])
def show_memory():
    memory = get_memory()
    return jsonify(memory)

@app.route('/')
def index():
    session.pop('google_token', None)
    return redirect(url_for('auth'))

@app.route("/logout")
def logout():
    session.pop('google_token', None)
    session.pop('chat_history', None)
    return redirect(url_for('auth'))

@app.route("/gmail")
def gmail_index():
    return send_from_directory('.', "index_gmail.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5003))
    print(f"🚀 Starting Flask app on http://localhost:{port}")
    print(f"📧 Gmail interface will be available at http://localhost:{port}/gmail")
    print(f"🔐 OAuth callback configured for http://localhost:{port}/oauth2callback")
    app.run(host='0.0.0.0', port=port, debug=True)