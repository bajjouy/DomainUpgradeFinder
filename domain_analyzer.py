import requests
import re
from urllib.parse import urlparse
import time
from typing import List, Dict, Optional

class DomainAnalyzer:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://serpapi.com/search"
    
    def extract_keywords(self, domain: str) -> List[str]:
        """
        Extract keywords from domain name by removing TLD and splitting into words
        """
        # Remove TLD
        domain_without_tld = re.sub(r'\.(com|net|org|edu|gov|mil|int|biz|info|name|pro|aero|coop|museum)$', '', domain.lower())
        
        # Split camelCase and handle various separators
        # First, handle camelCase by inserting spaces before uppercase letters
        domain_spaced = re.sub(r'([a-z])([A-Z])', r'\1 \2', domain_without_tld)
        
        # Replace common separators with spaces
        domain_spaced = re.sub(r'[-_.]', ' ', domain_spaced)
        
        # Split into words and filter out empty strings
        keywords = [word.strip().lower() for word in domain_spaced.split() if word.strip()]
        
        # Remove common words that don't add value
        stop_words = {'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        keywords = [word for word in keywords if word not in stop_words and len(word) > 1]
        
        return keywords
    
    def search_google(self, query: str, max_results: int = 10) -> List[Dict]:
        """
        Search Google using SerpAPI for the given query
        """
        params = {
            'q': f'"{query}"',  # Search exact phrase in quotes
            'api_key': self.api_key,
            'engine': 'google',
            'num': max_results,
            'start': 0
        }
        
        try:
            response = requests.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'error' in data:
                raise Exception(f"SerpAPI Error: {data['error']}")
            
            results = []
            organic_results = data.get('organic_results', [])
            
            for i, result in enumerate(organic_results[:max_results]):
                link = result.get('link', '')
                title = result.get('title', '')
                snippet = result.get('snippet', '')
                
                if link:
                    results.append({
                        'url': link,
                        'title': title,
                        'snippet': snippet,
                        'rank': i + 1
                    })
            
            return results
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {str(e)}")
        except Exception as e:
            raise Exception(f"Search error: {str(e)}")
    
    def extract_domain_from_url(self, url: str) -> str:
        """
        Extract domain name from URL
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain
        except:
            return ""
    
    def check_keyword_match(self, my_keywords: List[str], competitor_domain: str) -> Dict:
        """
        Check if all keywords from my domain are present in competitor domain
        """
        # Remove TLD from competitor domain
        competitor_clean = re.sub(r'\.(com|net|org|edu|gov|mil|int|biz|info|name|pro|aero|coop|museum)$', '', competitor_domain.lower())
        
        # Create a searchable string from competitor domain
        competitor_text = re.sub(r'[-_.]', ' ', competitor_clean).lower()
        competitor_text = re.sub(r'([a-z])([A-Z])', r'\1 \2', competitor_text)
        
        matches = []
        for keyword in my_keywords:
            if keyword in competitor_text:
                matches.append(keyword)
        
        return {
            'matches': matches,
            'match_count': len(matches),
            'total_keywords': len(my_keywords),
            'is_upgrade': len(matches) == len(my_keywords) and len(matches) > 0
        }
    
    def analyze_domain(self, domain: str, max_results: int = 10) -> List[Dict]:
        """
        Analyze a single domain and find upgrade opportunities
        """
        try:
            # Extract keywords
            keywords = self.extract_keywords(domain)
            
            if not keywords:
                return []
            
            # Create search query
            query = ' '.join(keywords)
            
            # Search Google
            search_results = self.search_google(query, max_results)
            
            if not search_results:
                return []
            
            # Analyze each result
            upgrade_opportunities = []
            
            for result in search_results:
                competitor_domain = self.extract_domain_from_url(result['url'])
                
                if not competitor_domain or competitor_domain == domain.lower():
                    continue
                
                # Check keyword match
                match_result = self.check_keyword_match(keywords, competitor_domain)
                
                # Only include if there are some matches (not necessarily all for upgrade)
                if match_result['match_count'] > 0:
                    upgrade_opportunities.append({
                        'My_Domain': domain,
                        'Competitor_Domain': competitor_domain,
                        'Keywords': ', '.join(keywords),
                        'Matched_Keywords': ', '.join(match_result['matches']),
                        'Match_Count': match_result['match_count'],
                        'Total_Keywords': match_result['total_keywords'],
                        'Is_Upgrade': match_result['is_upgrade'],
                        'Google_Rank': result['rank'],
                        'Competitor_Title': result['title']
                    })
            
            # Add small delay to respect rate limits
            time.sleep(0.5)
            
            return upgrade_opportunities
            
        except Exception as e:
            print(f"Error analyzing domain {domain}: {str(e)}")
            return []
