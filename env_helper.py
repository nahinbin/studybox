# Environment Configuration Helper
# Use this to switch between local and production settings

import os

def set_local_env():
    """Set environment variables for local development"""
    env_content = """SECRET_KEY=your-secret-key-here
MAIL_USERNAME=nahinbinmunir@gmail.com
MAIL_PASSWORD=hcuy yehd ohir fdcy
SERVER_NAME=localhost:5000
"""
    with open('.env', 'w') as f:
        f.write(env_content)
    print("✅ Local environment configured")

def set_production_env():
    """Set environment variables for production (Render)"""
    env_content = """SECRET_KEY=your-secret-key-here
MAIL_USERNAME=nahinbinmunir@gmail.com
MAIL_PASSWORD=hcuy yehd ohir fdcy
SERVER_NAME=studybox.onrender.com
"""
    with open('.env', 'w') as f:
        f.write(env_content)
    print("✅ Production environment configured")

if __name__ == "__main__":
    print("Environment Configuration Helper")
    print("1. Local development")
    print("2. Production (Render)")
    choice = input("Choose environment (1 or 2): ")
    
    if choice == "1":
        set_local_env()
    elif choice == "2":
        set_production_env()
    else:
        print("Invalid choice")
