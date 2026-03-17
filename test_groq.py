import requests
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")
print(f"API Key: {api_key[:10]}...")

# Test with current working models
models_to_test = [
    "llama-3.3-70b-versatile",
    "llama3-70b-8192",
    "llama3-8b-8192"
]

for model in models_to_test:
    print(f"\n🔍 Testing model: {model}")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": model,
        "messages": [
            {"role": "user", "content": "Say hello in one word"}
        ]
    }
    
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers,
        json=data
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print(f"✅ Working! Response: {response.json()['choices'][0]['message']['content']}")
        break
    else:
        print(f"❌ Failed: {response.text[:100]}")