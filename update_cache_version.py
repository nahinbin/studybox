#!/usr/bin/env python3
"""
Cache Version Update Script

This script updates the cache-busting version in your Flask app.
Run this script whenever you deploy updates to ensure users get the latest version.

Usage:
    python update_cache_version.py
"""

import os
import time
import re

def update_cache_version():
    """Update the cache version timestamp in app.py"""
    app_file = 'app.py'
    
    if not os.path.exists(app_file):
        print(f"{app_file} not found!")
        return False
    

    with open(app_file, 'r', encoding='utf-8') as f:
        content = f.read()
    

    new_version = str(int(time.time()))
    

    pattern = r"app\.config\['CACHE_BUST_VERSION'\] = str\(int\(time\.time\(\)\)\)"
    replacement = f"app.config['CACHE_BUST_VERSION'] = str(int(time.time()))"
    
    if pattern in content:

        new_content = re.sub(pattern, replacement, content)
        

        with open(app_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"Cache version updated to: {new_version}")
        print("Users will now get the latest version of your site!")
        return True
    else:
        print("Could not find cache version configuration in app.py")
        return False

if __name__ == "__main__":
    update_cache_version()
