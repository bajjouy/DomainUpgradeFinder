import requests
import re
from urllib.parse import urlparse
import time
import json
from typing import List, Dict, Optional, Tuple
from models import APIKey, SystemLog, APIKeyStatus, db
from datetime import datetime, timedelta
import logging

class APIRotationManager:
    def __init__(self):
        self.base_url = "https://google.serper.dev/search"
        self._current_key_index = 0
        self._batch_size = 5  # Maximum concurrent searches
        self._rate_limit_delay = 0.2  # Delay between batches in seconds
    
    def get_active_api_keys(self) -> List[APIKey]:
        """Get all active API keys ordered by usage count (least used first)"""
        return APIKey.query.filter_by(status=APIKeyStatus.ACTIVE).order_by(APIKey.usage_count.asc()).all()
    
    def get_next_api_key(self) -> Optional[APIKey]:
        """Get the next API key to use (round-robin with failover)"""
        active_keys = self.get_active_api_keys()
        
        if not active_keys:
            self._log_system("error", "No active API keys available")
            return None
        
        # Reset index if it's beyond the available keys
        if self._current_key_index >= len(active_keys):
            self._current_key_index = 0
        
        key = active_keys[self._current_key_index]
        self._current_key_index += 1
        
        return key
    
    def search_google_bulk(self, queries: List[str], max_results: int = 10, progress_callback=None) -> List[Tuple[str, List[Dict], Optional[str]]]:
        """
        Perform bulk searches with optimized batching and progress tracking
        Returns: List of (query, results, api_key_used) tuples
        """
        print(f"DEBUG: Starting bulk search with {len(queries)} queries")
        results = []
        total_queries = len(queries)
        
        if total_queries == 0:
            print("DEBUG: No queries to process")
            return results
        
        # Process queries in batches
        for i in range(0, total_queries, self._batch_size):
            batch = queries[i:i + self._batch_size]
            batch_results = []
            
            print(f"DEBUG: Processing batch {i//self._batch_size + 1}, queries {i+1}-{min(i+len(batch), total_queries)} of {total_queries}")
            
            for j, query in enumerate(batch):
                try:
                    print(f"DEBUG: Searching for query: '{query}'")
                    search_results, api_key_used = self.search_google_with_rotation(query, max_results)
                    batch_results.append((query, search_results, api_key_used))
                    print(f"DEBUG: Got {len(search_results)} results for query: '{query}'")
                except Exception as e:
                    print(f"DEBUG: Error for query '{query}': {str(e)}")
                    self._log_system("error", f"Bulk search failed for query '{query}': {str(e)}")
                    batch_results.append((query, [], None))
                
                # Progress callback
                if progress_callback:
                    progress = ((i + len(batch_results)) / total_queries) * 100
                    print(f"DEBUG: Progress callback: {progress}% for query '{query}'")
                    progress_callback(progress, query)
            
            results.extend(batch_results)
            
            # Rate limiting between batches
            if i + self._batch_size < total_queries:
                print(f"DEBUG: Sleeping for {self._rate_limit_delay}s between batches")
                time.sleep(self._rate_limit_delay)
        
        print(f"DEBUG: Bulk search completed with {len(results)} total results")
        return results
    
    def search_google_with_rotation(self, query: str, max_results: int = 10, max_retries: int = None) -> Tuple[List[Dict], Optional[str]]:
        """
        Search Google with API key rotation and failover with smart result count reduction
        Returns: (results, api_key_used)
        """
        active_keys = self.get_active_api_keys()
        
        if not active_keys:
            raise Exception("No active API keys available")
        
        # If max_retries not specified, try all available keys
        if max_retries is None:
            max_retries = len(active_keys)
        
        last_error = None
        attempts = 0
        current_max_results = max_results
        
        # Try with progressively smaller result counts if "Query not allowed"
        result_fallbacks = [max_results, 50, 30, 20, 10] if max_results > 10 else [max_results]
        
        for fallback_results in result_fallbacks:
            current_max_results = fallback_results
            
            for attempt in range(min(max_retries, len(active_keys))):
                api_key = self.get_next_api_key()
                
                if not api_key:
                    break
                
                try:
                    results = self._search_with_key(query, api_key, current_max_results)
                    
                    # Record successful usage
                    api_key.record_usage(success=True)
                    db.session.commit()
                    
                    if current_max_results < max_results:
                        self._log_system("info", f"Successful search with reduced results ({current_max_results}) for query: {query}")
                    else:
                        self._log_system("info", f"Successful search with API key: {api_key.key_name}")
                    
                    return results, api_key.key_name
                    
                except Exception as e:
                    last_error = str(e)
                    attempts += 1
                    
                    # Record failed usage
                    api_key.record_usage(success=False)
                    
                    # Check if we should deactivate this key
                    if self._should_deactivate_key(api_key, str(e)):
                        api_key.status = APIKeyStatus.FAILED
                        self._log_system("warning", f"Deactivated API key {api_key.key_name}: {str(e)}")
                    
                    db.session.commit()
                    
                    self._log_system("warning", f"API key {api_key.key_name} failed with {current_max_results} results: {str(e)}")
                    
                    # If it's a "Query not allowed" error, try with fewer results
                    if "Query not allowed" in str(e) and current_max_results > 10:
                        self._log_system("info", f"Trying with fewer results due to query restriction")
                        break  # Break to try next fallback count
                    
                    # Wait before trying next key (reduced for bulk processing)
                    time.sleep(0.1)
            
            # If we got "Query not allowed", try next fallback count
            if last_error and "Query not allowed" in last_error and current_max_results > 10:
                continue
            else:
                break  # If other error or we're already at 10 results, stop trying
        
        # All keys and fallbacks failed
        error_msg = f"All API keys failed after {attempts} attempts. Last error: {last_error}"
        self._log_system("error", error_msg)
        raise Exception(error_msg)
    
    def _search_with_key(self, query: str, api_key: APIKey, max_results: int) -> List[Dict]:
        """Search with a specific API key"""
        headers = {
            'X-API-KEY': api_key.key_value,
            'Content-Type': 'application/json'
        }
        
        payload = {
            'q': f'"{query}"',  # Search exact phrase in quotes
            'num': max_results,
            'gl': 'us',
            'hl': 'en'
        }
        
        response = requests.post(self.base_url, headers=headers, json=payload, timeout=30)
        
        # Handle different error types
        if response.status_code == 429:
            raise Exception("Rate limit exceeded")
        elif response.status_code == 401:
            raise Exception("Invalid API key")
        elif response.status_code >= 400:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
        
        response.raise_for_status()
        data = response.json()
        
        if 'message' in data and 'error' in data.get('message', '').lower():
            raise Exception(f"Serper API Error: {data['message']}")
        
        results = []
        organic_results = data.get('organic', [])
        
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
    
    def _should_deactivate_key(self, api_key: APIKey, error_message: str) -> bool:
        """Determine if an API key should be deactivated based on the error"""
        deactivate_errors = [
            'invalid api key',
            'authentication failed',
            'quota exceeded',
            'subscription expired',
            'account suspended'
        ]
        
        error_lower = error_message.lower()
        return any(err in error_lower for err in deactivate_errors)
    
    def _log_system(self, level: str, message: str, api_key_id: int = None):
        """Log system events"""
        log = SystemLog(
            level=level,
            message=message,
            api_key_id=api_key_id
        )
        db.session.add(log)
        
        # Also log to Python logger
        logger = logging.getLogger(__name__)
        if level == 'error':
            logger.error(message)
        elif level == 'warning':
            logger.warning(message)
        else:
            logger.info(message)

class EnhancedDomainAnalyzer:
    """Enhanced domain analyzer with API rotation support"""
    
    def __init__(self):
        self.api_manager = APIRotationManager()
    
    def parse_keywords(self, keywords_text: str) -> List[str]:
        """Parse keywords from text input and clean them"""
        if not keywords_text:
            return []
        
        # Split keywords by spaces and clean them
        keywords = [word.strip().lower() for word in keywords_text.split() if word.strip()]
        
        # Remove common words that don't add value
        stop_words = {'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        keywords = [word for word in keywords if word not in stop_words and len(word) > 1]
        
        return keywords
    
    def extract_domain_from_url(self, url: str) -> str:
        """Extract domain name from URL"""
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
        """Check if all keywords from my domain are present in competitor domain"""
        # Remove TLD from competitor domain
        competitor_clean = re.sub(r'\\.(com|net|org|edu|gov|mil|int|biz|info|name|pro|aero|coop|museum)$', '', competitor_domain.lower())
        
        # Create a searchable string from competitor domain
        competitor_text = re.sub(r'[-_.]', ' ', competitor_clean).lower()
        competitor_text = re.sub(r'([a-z])([A-Z])', r'\\1 \\2', competitor_text)
        
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
    
    def analyze_keywords(self, keywords_text: str, max_results: int = 10) -> Tuple[List[Dict], Optional[str]]:
        """
        Analyze keywords and find upgrade opportunities with API rotation
        Returns: (upgrade_opportunities, api_key_used)
        """
        start_time = time.time()
        
        try:
            # Parse keywords
            keywords = self.parse_keywords(keywords_text)
            
            if not keywords:
                return [], None
            
            # Create search query
            query = ' '.join(keywords)
            
            # Search Google with API rotation
            search_results, api_key_used = self.api_manager.search_google_with_rotation(query, max_results)
            
            if not search_results:
                return [], api_key_used
            
            # Analyze each result
            upgrade_opportunities = []
            
            for result in search_results:
                competitor_domain = self.extract_domain_from_url(result['url'])
                
                if not competitor_domain:
                    continue
                
                # Check keyword match
                match_result = self.check_keyword_match(keywords, competitor_domain)
                
                # Only include if there are some matches (not necessarily all for upgrade)
                if match_result['match_count'] > 0:
                    upgrade_opportunities.append({
                        'Keywords': keywords_text,
                        'Competitor_Domain': competitor_domain,
                        'Search_Keywords': ', '.join(keywords),
                        'Matched_Keywords': ', '.join(match_result['matches']),
                        'Match_Count': match_result['match_count'],
                        'Total_Keywords': match_result['total_keywords'],
                        'Is_Upgrade': match_result['is_upgrade'],
                        'Google_Rank': result['rank'],
                        'Competitor_Title': result['title']
                    })
            
            return upgrade_opportunities, api_key_used
            
        except Exception as e:
            # Log the error
            logging.error(f"Error analyzing keywords {keywords_text}: {str(e)}")
            raise e