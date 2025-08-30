#!/usr/bin/env python3
"""
Entry point that runs Flask app even when called with 'streamlit run app.py'.
This bypasses Streamlit and directly runs the Flask application.
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Check if this is being run by streamlit
if 'streamlit' in sys.modules or any('streamlit' in arg for arg in sys.argv):
    # If called by streamlit, we'll run Flask instead
    print("Streamlit detected, starting Flask application instead...")
    os.system(f"{sys.executable} app_flask.py")
    sys.exit(0)

# Direct execution - run Flask app
if __name__ == '__main__':
    try:
        from app_flask import create_app
        
        app = create_app()
        
        # Get port from environment variable or default to 5000
        port = int(os.environ.get('PORT', 5000))
        
        print(f"Starting Flask application on port {port}")
        app.run(
            host='0.0.0.0',
            port=port,
            debug=False
        )
        
    except Exception as e:
        print(f"Error starting Flask application: {e}")
        # Fallback: try running app_flask.py directly
        os.system(f"{sys.executable} app_flask.py")
        sys.exit(1)