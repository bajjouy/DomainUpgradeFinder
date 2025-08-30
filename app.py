#!/usr/bin/env python3
"""
Entry point that runs the Flask application directly for deployment.
This ensures the Flask landing page shows up at the main deployment URL.
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Run the Flask application directly."""
    try:
        from app_flask import create_app
        
        app = create_app()
        
        # Get port from environment variable or default to 5000
        port = int(os.environ.get('PORT', 5000))
        
        print(f"Starting Domain Upgrade Pro SaaS on port {port}")
        app.run(
            host='0.0.0.0',
            port=port,
            debug=False  # Disable debug in production deployment
        )
        
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()