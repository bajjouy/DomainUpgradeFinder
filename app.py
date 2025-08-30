#!/usr/bin/env python3
"""
Entry point for deployment that works with both Streamlit and Flask deployment configurations.
This file serves as a bridge to run the Flask application regardless of the deployment command.
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Main entry point that runs the Flask application."""
    try:
        # Import and run the Flask application
        from app_flask import create_app
        
        app = create_app()
        
        # Get port from environment variable or default to 5000
        port = int(os.environ.get('PORT', 5000))
        
        # Run the Flask app
        app.run(
            host='0.0.0.0',
            port=port,
            debug=False  # Disable debug in deployment
        )
        
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()