# Overview

Domain Upgrade Finder is a Streamlit-based web application that analyzes domain names to identify potential buyers by finding businesses that already rank on Google with similar keywords. The app extracts keywords from domain names, searches for exact keyword phrases on Google, and identifies competitor domains that could benefit from upgrading to a more premium domain name. This creates a data-driven approach to domain sales by targeting businesses that are already established in the market but using less optimal domain names.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
The application uses **Streamlit** as the primary web framework, providing a single-page application with an intuitive interface. The UI is structured with:
- Main content area with two-column layout for input and results
- Sidebar for configuration settings including API keys and search parameters
- Session state management for maintaining analyzer instances and results across interactions

## Backend Architecture
The system follows a **modular, object-oriented design** with clear separation of concerns:
- **DomainAnalyzer class** handles the core business logic for domain analysis and Google search integration
- **KeywordExtractor class** (referenced but not fully implemented) manages domain name parsing and keyword extraction
- **Utility functions** provide domain validation and text parsing capabilities

## Data Processing Pipeline
The application implements a **multi-step analysis pipeline**:
1. **Domain Input Processing** - Validates and parses domain lists from user input
2. **Keyword Extraction** - Removes TLDs and splits domain names into searchable keywords using regex patterns
3. **Google Search Integration** - Performs exact phrase searches using SerpAPI
4. **Competitor Analysis** - Extracts domains from search results and performs keyword matching
5. **Upgrade Identification** - Determines if the user's domain represents an upgrade opportunity

## Search Strategy
The system uses **exact phrase searching** with quoted queries to ensure precise keyword matching. The keyword extraction algorithm handles various domain naming conventions including camelCase, hyphens, underscores, and removes common stop words to improve search accuracy.

## State Management
The application uses **Streamlit's session state** to maintain analyzer instances and results between user interactions, ensuring API keys and configuration persist throughout the user session.

# External Dependencies

## Search API Integration
- **SerpAPI** - Primary integration for Google search functionality, requiring API key authentication
- Used for retrieving top 10 search results for keyword phrases
- Handles rate limiting and response parsing

## Python Libraries
- **Streamlit** - Web application framework and UI components
- **Pandas** - Data manipulation and analysis (imported but usage not shown in current code)
- **Requests** - HTTP client for API communications with SerpAPI
- **urllib.parse** - URL parsing and domain extraction utilities

## Development Dependencies
- **Python standard library** modules including `re`, `os`, `io`, `time`, and `typing` for core functionality
- Configuration management through environment variables and Streamlit config files

## Infrastructure Requirements
- The application expects to run on port 5000 with headless configuration
- Requires internet connectivity for SerpAPI integration
- No database dependencies identified in current implementation