import requests
import os

class GroqService:
    def __init__(self, api_key):
        self.api_key = api_key
        self.model = "llama-3.3-70b-versatile"
    
    def generate(self, prompt):
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7,
                "max_tokens": 1024
            }
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            else:
                return f"AI Error: {response.status_code}"
        except Exception as e:
            return f"Error: {str(e)}"