# 📧 Gmail Chatbot - AI-Powered Email Assistant

An intelligent email management system that uses AI to help you draft, send, analyze, and summarize your Gmail messages through a conversational interface.

<img width="1895" height="914" alt="image" src="https://github.com/user-attachments/assets/d3ffc9c6-f013-433f-a4ec-0a627730abc8" />

## ✨ Features

- **🤖 AI-Powered Email Composition**: Draft and send emails using natural language
- **📊 Email Analysis**: Analyze recent emails with AI-generated summaries
- **🔍 Smart Search**: Search emails by subject, sender, or content
- **📝 Draft Management**: Create and manage email drafts
- **👥 Contact Integration**: Load contacts from Excel/CSV files
- **🌐 Web Interface**: Modern, responsive chat interface
- **🔐 Secure OAuth2**: Google OAuth2 authentication
- **💬 Natural Language Processing**: Understands conversational commands
- **📑 Email Summarization**: Get concise summaries of email threads

## 🛠️ Tech Stack

- **Backend**: Flask (Python)
- **AI Model**: Mistral AI API
- **Email API**: Gmail API (Google)
- **Authentication**: OAuth2
- **Frontend**: HTML/CSS/JavaScript
- **Data**: Pandas (Excel/CSV handling)
- **Containerization**: Docker (optional)

## 📋 Prerequisites

- Python 3.8+
- Gmail account
- Google Cloud Project with Gmail API enabled
- Mistral AI API key
- Docker (optional, for containerized deployment)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Albekbashy/Gmail_Chatbot.git
cd Gmail_Chatbot
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Up Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Gmail API
4. Create OAuth 2.0 credentials (Desktop app)
5. Download credentials as `credentials.json`
6. Place `credentials.json` in the project root
7. Go to OAuth consent screen in the left sidebar:
  - Set User Type to External
  - Add your Google account(s) under Test users (only these accounts can access the app during testing)
  - Save and continue setup
  - ⚠️ Note: If you don’t add your Gmail account as a test user, OAuth authentication will fail with an “Access blocked” or “Unauthorized user” error.

### 4. Set Up Environment Variables

Create a `.env` file in the project root:

```env
MISTRAL_API_KEY_3=your_mistral_api_key_here
CSV_FILE_PATH=https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID/edit
PORT=5003
```

### 5. Prepare Contacts File

Create a contacts file (Excel or Google Sheets) with columns:
- `Nom` (Name)
- `Email` (Email address)

## 🎯 Usage

### Start the Server

```bash
python app.py
```

The application will be available at:
- **Main interface**: `http://localhost:5003/gmail`
- **OAuth callback**: `http://localhost:5003/oauth2callback`

### Using the Chatbot

**Send an Email:**
```
Send an email to John telling him the meeting is at 3pm
```

**Create a Draft:**
```
Draft an email to Sarah about the project update
```

**Analyze Emails:**
```
Analyze my emails from the last 7 days
```

**Search Emails:**
```
Show me emails with subject containing "invoice"
```

**Summarize Emails:**
```
Summarize emails about the marketing campaign
```

**Congratulate Someone:**
```
Send an email to Pierre and congratulate him for his exam success
```

## 📁 Project Structure

```
gmail-chatbot/
├── __pycache__/           # Python cache files
├── app.py                 # Main Flask application
├── email_assistant.py     # Email operations helper
├── gmail_agent.py         # Gmail API integration
├── mistral_client.py      # Mistral AI client
├── index_gmail.html       # Web interface
├── credentials.json       # Google OAuth credentials (not in repo)
├── .env                   # Environment variables (not in repo)
├── requirements.txt       # Python dependencies
├── tools.json            # Configuration file
├── .gitignore           # Git ignore file
└── README.md            # This file
```

## 🔧 Core Components

### app.py
Main Flask application handling:
- OAuth2 authentication flow
- Chat endpoint for AI interactions
- Email sending and drafting
- Session management
- Web interface routing

### gmail_agent.py
Gmail API integration providing:
- Email retrieval and search
- Draft creation and management
- Email analysis
- Body text extraction

### mistral_client.py
Mistral AI integration for:
- Natural language understanding
- Email summarization
- Importance detection
- Response generation

### email_assistant.py
Command-line email assistant for:
- Direct email operations
- Contact resolution
- Draft and send functionality

## 🔑 API Scopes

The application requires the following Gmail API scopes:
- `gmail.send` - Send emails
- `gmail.readonly` - Read emails
- `gmail.modify` - Modify emails
- `gmail.compose` - Compose drafts

## 🔒 Security Notes

- ⚠️ **Never commit** `credentials.json`, `token.json`, or `.env` files
- 🔐 Keep your API keys secure
- 🌍 Use environment variables for sensitive data
- 🔄 The app uses Flask sessions for OAuth state management
- 🛡️ OAuth tokens are stored in session, not in files (for web deployment)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🐛 Troubleshooting

### OAuth Redirect Issues
- Ensure redirect URI in Google Cloud Console matches `http://localhost:5003/oauth2callback`
- Check that PORT in `.env` matches the running port

### Mistral API Errors
- Verify API key is correct in `.env`
- Check API rate limits (429 errors)
- Ensure you're using `MISTRAL_API_KEY_3` as the environment variable name

### Contact Resolution Errors
- Ensure contacts file has correct column names: `Nom` and `Email`
- Check CSV/Excel file path in `.env`
- Verify the Google Sheets link has proper export permissions

### Python Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --upgrade
```

### Port Already in Use
```bash
# Change port in .env or kill existing process
lsof -ti:5003 | xargs kill -9  # Mac/Linux
netstat -ano | findstr :5003   # Windows
```

## 🔄 Environment Variables Explained

| Variable | Description | Example |
|----------|-------------|---------|
| `MISTRAL_API_KEY_3` | Your Mistral AI API key | `sk-...` |
| `CSV_FILE_PATH` | Path/URL to contacts file | Google Sheets URL |
| `PORT` | Port to run the server on | `5003` |

## 📊 Features in Detail

### Email Analysis
Analyzes emails and provides:
- Sender information
- Subject line
- AI-generated summary
- Importance assessment

### Smart Search
Supports multiple search strategies:
- Subject-based search
- Body content search
- Sender-based search
- Date-range filtering

### Natural Language Commands
Understands various phrasings:
- "Send email to..."
- "Draft a message for..."
- "Tell [person] that..."
- "Analyze emails about..."

## 🎨 Web Interface

The chatbot includes a modern web interface (`index_gmail.html`) with:
- Dark theme design
- Real-time chat interface
- Formatted email previews
- Responsive layout
- Session management

## 📧 Contact

For questions or support, please open an issue on GitHub.

## 🙏 Acknowledgments

- Google Gmail API
- Mistral AI
- Flask Framework
- Python Community


---

**Made with ❤️ using Flask, Gmail API, and Mistral AI**
