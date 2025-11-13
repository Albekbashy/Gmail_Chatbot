import requests
import os
from dotenv import load_dotenv

load_dotenv()
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY_3")

def query_mistral(prompt, system="Tu es un assistant IA professionnel."):
    """
    Query Mistral API with better error handling
    """
    if not MISTRAL_API_KEY:
        print("⚠️ MISTRAL_API_KEY_3 not found in environment")
        raise Exception("Mistral API key not configured")
    
    url = "https://api.mistral.ai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {MISTRAL_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "mistral-medium",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        
        # Handle rate limiting
        if response.status_code == 429:
            print("⚠️ Mistral rate limit hit (429)")
            raise Exception("⛔ Mistral API rate limit reached. Please wait a few minutes and try again.")
        
        # Handle authentication errors
        if response.status_code == 401:
            print("⚠️ Mistral authentication failed (401)")
            raise Exception("⛔ Mistral API authentication failed. Please check your API key.")
        
        # Handle other errors
        if response.status_code != 200:
            print(f"⚠️ Mistral API error: {response.status_code}")
            print(f"Response: {response.text}")
            raise Exception(f"⛔ Mistral API error ({response.status_code}): {response.text}")
        
        response.raise_for_status()
        result = response.json()
        
        if "choices" not in result or len(result["choices"]) == 0:
            raise Exception("⛔ Mistral returned empty response")
        
        return result["choices"][0]["message"]["content"].strip()
        
    except requests.exceptions.Timeout:
        print("⚠️ Mistral request timeout")
        raise Exception("⛔ Mistral API request timed out. Please try again.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Mistral request exception: {e}")
        raise Exception(f"⛔ Mistral API connection error: {str(e)}")
    except Exception as e:
        # Re-raise if already formatted error
        if str(e).startswith("⛔"):
            raise
        print(f"⚠️ Unexpected Mistral error: {e}")
        raise Exception(f"⛔ Mistral error: {str(e)}")
