import re
from typing import List, Optional

class KeywordExtractor:
    """Class to handle keyword extraction from domain names"""
    
    def __init__(self):
        # Common TLDs to remove
        self.tlds = [
            '.com', '.net', '.org', '.info', '.biz', '.co', '.io', '.ai',
            '.app', '.dev', '.tech', '.online', '.store', '.shop', '.site',
            '.website', '.xyz', '.club', '.pro', '.me', '.tv', '.cc',
            '.ly', '.be', '.it', '.us', '.uk', '.ca', '.au', '.de', '.fr'
        ]
        
        # Common word separators in domain names
        self.separators = ['-', '_', '.# thoughts
This is a comprehensive domain upgrade finder application that needs to analyze domains and find potential buyers by comparing with Google search results. The app will use Streamlit for the frontend, SerpAPI for Google searches, and pandas for data processing. Key features include domain keyword extraction, automated Google searching, competitor domain extraction, keyword matching logic, and CSV/Excel export functionality. I'll need to implement proper error handling for API limits and provide real-time progress updates.

# useful_guidelines_from_blueprints
- Use `.streamlit/config.toml` for server configuration with headless=true, address="0.0.0.0", port=5000
- Use `st.rerun()` instead of `experimental_rerun`
- Maintain default font settings unless specifically requested
- Focus on content organization and interactive elements
- Use standard Streamlit functions for application flow control

# directory_structure
```json
[
    {"path": ".streamlit/config.toml", "status": "new"},
    {"path": "app.py", "status": "new"},
    {"path": "domain_analyzer.py", "status": "new"},
    {"path": "utils.py", "status": "new"}
]
