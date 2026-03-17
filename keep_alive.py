import time
import requests
from datetime import datetime

# Replace this with your actual Render URL after deployment
YOUR_RENDER_URL = "https://your-app-name.onrender.com"

def ping():
    try:
        # Ping the health endpoint (doesn't wake the whole app)
        response = requests.get(f"{YOUR_RENDER_URL}/health", timeout=10)
        print(f"[{datetime.now()}] ✅ Ping successful: {response.status_code}")
    except Exception as e:
        print(f"[{datetime.now()}] ❌ Ping failed: {e}")

if __name__ == "__main__":
    print("🚀 Keep-alive script started - pinging every 10 minutes")
    print(f"Target: {YOUR_RENDER_URL}")
    
    while True:
        ping()
        time.sleep(600)  # 10 minutes