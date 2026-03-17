import webbrowser
import time
import subprocess
import os
import sys

print("🚀 Starting AI Gateway Server...")

# Start the server and keep it running
server_process = subprocess.Popen([sys.executable, "main.py"])

# Wait longer for server to start
print("⏳ Waiting for server to start (10 seconds)...")
time.sleep(10)

# Check if server process is still running
if server_process.poll() is None:
    print("✅ Server is running!")
    
    # Open login page
    login_url = "http://localhost:8000/login"
    print(f"📂 Opening: {login_url}")
    webbrowser.open(login_url)
    
    print("\n📝 If browser didn't open, go to: http://localhost:8000/login")
    print("\n⚠️  To stop server: Press Ctrl+C in this terminal")
    
    # Keep the script running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping server...")
        server_process.terminate()
        print("👋 Goodbye!")
else:
    print("❌ Server failed to start!")
    print("Check main.py for errors")