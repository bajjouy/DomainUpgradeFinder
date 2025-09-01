"""
Business Search Service for Google Maps Places integration via Serper.dev
"""
import time
import threading
from typing import Dict, List, Optional
from datetime import datetime
from models import db, BusinessSearchSession, BusinessData, User
from api_rotation import APIRotationManager
from serper_api_utils import search_google_web_serper, extract_email_from_website
from cache_manager import CacheManager
import json
import logging

logger = logging.getLogger(__name__)

class BusinessSearchService:
    """
    Service class for searching businesses using Serper.dev Places API
    Integrates with existing API rotation and caching infrastructure
    """
    
    def __init__(self):
        self.active_sessions = {}  # Track active search sessions
        self.api_manager = APIRotationManager()
        self.cache_manager = CacheManager()
        
    def start_business_search(self, user_id: int, keywords: str, cities: List[str], 
                            max_results_per_city: int = 20) -> int:
        """
        Start a new business search session
        
        Args:
            user_id: ID of the user initiating search
            keywords: Business keywords to search for
            cities: List of cities to search in
            max_results_per_city: Maximum results per city (default 20)
        
        Returns:
            Session ID for tracking progress
        """
        # Create new search session
        session = BusinessSearchSession()
        session.user_id = user_id
        session.keywords = keywords
        session.set_cities_list(cities)
        session.max_results_per_city = max_results_per_city
        session.status = 'processing'
        session.progress = 0.0
        
        db.session.add(session)
        db.session.commit()
        
        # Start background processing
        thread = threading.Thread(
            target=self._process_business_search_background,
            args=(session.id,),
            daemon=True
        )
        thread.start()
        
        logger.info(f"Started business search session {session.id} for user {user_id}")
        return session.id
    
    def _process_business_search_background(self, session_id: int):
        """
        Background processing of business search
        
        Args:
            session_id: ID of search session to process
        """
        from app_flask import create_app
        
        try:
            # Create Flask app context for background thread
            app = create_app()
            with app.app_context():
                session = BusinessSearchSession.query.get(session_id)
                if not session:
                    logger.error(f"Session {session_id} not found")
                    return
                
                start_time = time.time()
                cities = session.get_cities_list()
                total_cities = len(cities)
                total_businesses_found = 0
                
                self.active_sessions[session_id] = {
                    'status': 'processing',
                    'progress': 0.0,
                    'current_location': None,
                    'total_businesses': 0
                }
                
                logger.info(f"Processing {len(cities)} cities for session {session_id}")
                
                for i, city in enumerate(cities):
                    try:
                        # Update progress
                        progress = (i / total_cities) * 100
                        session.progress = progress
                        session.current_location = city
                        
                        self.active_sessions[session_id].update({
                            'progress': progress,
                            'current_location': city
                        })
                        
                        db.session.commit()
                        
                        # Handle bulk search - create separate sessions for each keyword
                        keywords_list = [kw.strip() for kw in session.keywords.split('\n') if kw.strip()]
                        
                        if len(keywords_list) > 1:
                            # Multiple keywords - create separate sessions for each
                            child_sessions = []
                            for keyword in keywords_list:
                                logger.info(f"🔍 Creating separate session for keyword: '{keyword}'")
                                
                                # Create child session for this keyword
                                child_session = BusinessSearchSession()
                                child_session.user_id = session.user_id
                                child_session.keywords = keyword  # Single keyword
                                child_session.cities = session.cities
                                child_session.max_results_per_city = session.max_results_per_city
                                child_session.status = 'processing'
                                child_session.progress = 0.0
                                child_session.parent_session_id = session.id  # Link to parent
                                child_session.created_at = session.created_at
                                db.session.add(child_session)
                                db.session.flush()
                                child_sessions.append(child_session)
                                
                                # Search for this exact keyword using web search (no location)
                                businesses = self._search_web_results_paginated(
                                    keyword, session.max_results_per_city, child_session.id
                                )
                                
                                # Save businesses for this child session
                                for business_data in businesses:
                                    business = BusinessData()
                                    business.session_id = child_session.id
                                    business.user_id = session.user_id
                                    business.keywords_searched = keyword
                                    business.city = city
                                    
                                    # Focus on URLs and titles (simplified data)
                                    business.name = business_data.get('name', '')
                                    business.website = business_data.get('website', '')
                                    business.address = business_data.get('description', '')
                                    business.phone = business_data.get('phone', '')
                                    business.rating = business_data.get('rating')
                                    business.user_ratings_total = business_data.get('user_ratings_total')
                                    business.price_level = business_data.get('price_level')
                                    business.business_status = 'UNKNOWN'
                                    business.latitude = None
                                    business.longitude = None
                                    business.place_id = None
                                    business.email = None
                                    business.types = json.dumps([])
                                    business.opening_hours = json.dumps([])
                                    
                                    db.session.add(business)
                                
                                # Mark child session as completed
                                child_session.status = 'completed'
                                child_session.progress = 100.0
                                child_session.completed_at = datetime.utcnow()
                                child_session.processing_time = (child_session.completed_at - child_session.created_at).total_seconds()
                                
                                logger.info(f"✅ Completed separate session for '{keyword}': {len(businesses)} results")
                            
                            db.session.commit()
                            
                            # Mark parent session as completed
                            session.status = 'completed'
                            session.progress = 100.0
                            session.completed_at = datetime.utcnow()
                            session.processing_time = (session.completed_at - session.created_at).total_seconds()
                            
                            logger.info(f"✅ Completed bulk search with {len(child_sessions)} separate keyword sessions")
                            return  # Exit early - we handled everything
                        
                        else:
                            # Single keyword - do exact web search (not location-based)
                            keyword = keywords_list[0] if keywords_list else session.keywords
                            businesses = self._search_web_results_paginated(
                                keyword, session.max_results_per_city, session_id
                            )
                            
                            # Tag each business with the keyword
                            for business in businesses:
                                business['search_keyword'] = keyword
                        
                        # Save businesses page by page with real-time updates
                        saved_count = 0
                        for i, business_data in enumerate(businesses, 1):
                            try:
                                business = BusinessData()
                                business.session_id = session.id
                                business.user_id = session.user_id
                                business.keywords_searched = business_data.get('search_keyword', session.keywords)
                                business.city = city
                                
                                # Focus on URLs and titles (simplified data)
                                business.name = business_data.get('name', '')  # This will be the page title
                                business.website = business_data.get('website', '')  # This will be the URL
                                business.address = business_data.get('description', '')  # Use description field for snippet
                                
                                # Set minimal required fields
                                business.phone = business_data.get('phone', '')
                                business.rating = business_data.get('rating')
                                business.user_ratings_total = business_data.get('user_ratings_total')
                                business.price_level = business_data.get('price_level')
                                business.business_status = 'UNKNOWN'
                                business.latitude = None
                                business.longitude = None
                                business.place_id = None
                                business.email = None
                                
                                # Set JSON fields with minimal data
                                business.types = json.dumps([])
                                business.opening_hours = json.dumps([])
                                
                                db.session.add(business)
                                db.session.flush()  # Flush to catch errors early
                                saved_count += 1
                                
                                # Update progress per business found
                                if i % 5 == 0:  # Update every 5 businesses
                                    session.current_location = f"{city} - {saved_count}/{len(businesses)} businesses saved"
                                    self.active_sessions[session_id].update({
                                        'current_location': session.current_location,
                                        'total_businesses': total_businesses_found + saved_count
                                    })
                                    db.session.commit()
                                    
                            except Exception as e:
                                logger.error(f"Error saving business {business_data.get('name', 'Unknown')}: {str(e)}")
                                db.session.rollback()
                                continue
                        
                        # Final commit for this city
                        try:
                            db.session.commit()
                            total_businesses_found += saved_count
                            logger.info(f"✅ Successfully saved {saved_count}/{len(businesses)} businesses for {city}")
                        except Exception as e:
                            logger.error(f"❌ Error committing businesses for {city}: {str(e)}")
                            db.session.rollback()
                        logger.info(f"Found {len(businesses)} businesses in {city}")
                        
                        # Small delay to respect rate limits
                        time.sleep(0.5)
                        
                    except Exception as e:
                        logger.error(f"Error processing city {city}: {str(e)}")
                        continue
                
                # Verify actual businesses saved before marking as completed
                actual_count = BusinessData.query.filter_by(session_id=session_id).count()
                logger.info(f"Verification: {actual_count} businesses actually saved vs {total_businesses_found} expected")
                
                # Mark session as completed
                end_time = time.time()
                session.status = 'completed'
                session.progress = 100.0
                session.total_businesses_found = actual_count  # Use actual count
                session.processing_time = end_time - start_time
                session.completed_at = datetime.utcnow()
                
                # Commit session completion separately
                try:
                    db.session.commit()
                    logger.info(f"Session {session_id} marked as completed successfully with {actual_count} businesses")
                except Exception as e:
                    logger.error(f"Error marking session as completed: {str(e)}")
                    db.session.rollback()
                
                # Update active sessions
                self.active_sessions[session_id] = {
                    'status': 'completed',
                    'progress': 100.0,
                    'current_location': 'Completed',
                    'total_businesses': total_businesses_found
                }
                
                logger.info(f"Completed session {session_id}: {total_businesses_found} businesses found")
            
        except Exception as e:
            logger.error(f"Critical error in session {session_id}: {str(e)}")
            # Mark session as failed
            try:
                session = BusinessSearchSession.query.get(session_id)
                if session:
                    session.status = 'failed'
                    session.progress = 0.0
                    db.session.commit()
                    
                if session_id in self.active_sessions:
                    self.active_sessions[session_id]['status'] = 'failed'
            except:
                pass
    
    def _search_web_results_paginated(self, keyword: str, max_results: int, session_id: int) -> List[Dict]:
        """
        Search for exact keyword matches using Google web search - returns URLs and titles
        """
        from serper_api_utils import search_google_web_serper
        from api_keys import get_working_serper_key
        
        all_results = []
        max_per_request = 100  # Serper API limit per request
        
        # For large result counts, we'll need multiple requests
        total_pages = (max_results + max_per_request - 1) // max_per_request  # Ceiling division
        
        logger.info(f"🔍 Starting exact keyword search for '{keyword}' (target: {max_results} URLs)")
        
        try:
            # Get API key
            api_key = get_working_serper_key()
            if not api_key:
                logger.error("❌ No working Serper API key found")
                return []
            
            # Search multiple pages if needed for large result counts
            for page in range(1, total_pages + 1):
                results_needed = min(max_per_request, max_results - len(all_results))
                start_index = (page - 1) * max_per_request
                
                logger.info(f"📄 Page {page}/{total_pages}: Searching for '{keyword}' (results {start_index+1}-{start_index+results_needed})...")
                
                # Update session status for pagination
                if session_id in self.active_sessions:
                    self.active_sessions[session_id].update({
                        'current_location': f"'{keyword}' - Page {page}/{total_pages} (searching...)",
                        'total_businesses': len(all_results)
                    })
                
                search_results = search_google_web_serper(
                    api_key=api_key,
                    query=keyword,  # Exact keyword search
                    location=None,  # No location - pure keyword search
                    num_results=results_needed,
                    start=start_index  # Pagination offset
                )
                
                if search_results.get('error'):
                    logger.error(f"❌ Search error on page {page}: {search_results['error']}")
                    break
                
                page_businesses = search_results.get('businesses', [])
                
                # Add rank information to each result
                for i, business in enumerate(page_businesses):
                    business['Rank'] = start_index + i + 1  # Global rank across all pages
                    business['Keywords Found'] = keyword
                    business['Search Date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                all_results.extend(page_businesses)
                
                logger.info(f"✅ Page {page}: Found {len(page_businesses)} URLs (Total: {len(all_results)}/{max_results})")
                
                # Update session status after page
                if session_id in self.active_sessions:
                    self.active_sessions[session_id].update({
                        'current_location': f"'{keyword}' - Page {page}/{total_pages}: {len(page_businesses)} URLs found",
                        'total_businesses': len(all_results)
                    })
                
                # Only stop if we get significantly fewer results (< 80% of expected)
                # This allows us to continue even if Google returns slightly fewer results per page
                if len(page_businesses) < (results_needed * 0.8):
                    logger.info(f"🏁 Reached end of results for '{keyword}' (got {len(page_businesses)}, expected {results_needed})")
                    break
                
                # Stop if we've reached our target
                if len(all_results) >= max_results:
                    break
                    
                # Rate limiting between pages
                import time
                time.sleep(0.5)
            
            logger.info(f"✅ Completed search for '{keyword}': {len(all_results)} total URLs found")
            return all_results
            
        except Exception as e:
            logger.error(f"❌ Error searching for keyword '{keyword}': {str(e)}")
            return []
    
    def _search_businesses_paginated(self, keywords: str, city: str, max_results: int, session_id: int) -> List[Dict]:
        """
        Search businesses page by page with real-time updates
        
        Args:
            keywords: Business keywords to search for
            city: City to search in
            max_results: Maximum total results to find
            session_id: Session ID for progress updates
        
        Returns:
            List of all business data found across pages
        """
        all_businesses = []
        page = 1
        per_page = 20  # Get 20 results per page
        total_found = 0
        
        logger.info(f"🔍 Starting paginated search for '{keywords}' in {city} (max {max_results} results)")
        
        while total_found < max_results:
            remaining = max_results - total_found
            current_page_size = min(per_page, remaining)
            
            logger.info(f"📄 Searching page {page} ({current_page_size} results)...")
            
            # Update progress to show current page being searched
            if session_id in self.active_sessions:
                self.active_sessions[session_id].update({
                    'current_location': f"{city} - Page {page} (searching...)",
                    'total_businesses': total_found
                })
            
            # Search this page
            page_businesses = self._search_single_page(keywords, city, current_page_size)
            
            if not page_businesses:
                logger.info(f"🛑 No more results found on page {page}, stopping search")
                break
                
            all_businesses.extend(page_businesses)
            total_found += len(page_businesses)
            
            # Update progress with page results
            if session_id in self.active_sessions:
                self.active_sessions[session_id].update({
                    'current_location': f"{city} - Page {page}: {len(page_businesses)} businesses found (Total: {total_found})",
                    'total_businesses': total_found
                })
            
            logger.info(f"✅ Page {page}: Found {len(page_businesses)} businesses (Total: {total_found}/{max_results})")
            
            # If we got fewer results than requested, we've reached the end
            if len(page_businesses) < current_page_size:
                logger.info(f"🏁 Reached end of results (got {len(page_businesses)}, expected {current_page_size})")
                break
                
            page += 1
            time.sleep(1)  # Rate limiting between pages
        
        logger.info(f"🎯 Completed search for {city}: {total_found} total businesses found across {page} pages")
        return all_businesses
    
    def _search_single_page(self, keywords: str, city: str, max_results: int) -> List[Dict]:
        """
        Search for businesses in a specific city (single page) using Serper.dev
        
        Args:
            keywords: Business keywords to search for
            city: City to search in
            max_results: Maximum number of results
        
        Returns:
            List of business data dictionaries
        """
        # Check cache first
        cache_key = f"business_search:{keywords}:{city}:{max_results}"
        cached_result = self.cache_manager.cache.get(
            "business_search",
            {
                'keywords': keywords,
                'city': city,
                'max_results': max_results
            }
        )
        
        if cached_result:
            logger.info(f"Using cached results for {keywords} in {city}")
            return cached_result.get('businesses', [])
        
        # Get API key using existing rotation system
        api_key_obj = self.api_manager.get_next_api_key()
        if not api_key_obj:
            logger.error("No API keys available for business search")
            return []
        
        api_key_value = api_key_obj.key_value
        
        try:
            # Search using Google web search with business extraction
            result = search_google_web_serper(
                api_key=api_key_value,
                query=keywords,
                location=city,
                num_results=max_results
            )
            
            if result['error']:
                logger.error(f"Serper API error: {result['error']}")
                # Record API failure
                api_key_obj.record_usage(success=False)
                db.session.commit()
                return []
            
            # Record successful API usage
            api_key_obj.record_usage(success=True)
            db.session.commit()
            
            businesses = result.get('businesses', [])
            
            # Cache the results for 30 minutes
            cache_data = {
                'businesses': businesses,
                'search_info': result.get('search_info', {}),
                'total_found': len(businesses)
            }
            self.cache_manager.cache.set(
                "business_search",
                {
                    'keywords': keywords,
                    'city': city,
                    'max_results': max_results
                },
                cache_data,
                ttl=1800  # 30 minutes
            )
            
            logger.info(f"Found {len(businesses)} businesses for {keywords} in {city}")
            return businesses
            
        except Exception as e:
            logger.error(f"Error searching businesses: {str(e)}")
            # Record API failure
            api_key_obj.record_usage(success=False)
            db.session.commit()
            return []
    
    def get_session_status(self, session_id: int) -> Dict:
        """
        Get current status of a search session
        
        Args:
            session_id: ID of search session
        
        Returns:
            Dictionary with session status information
        """
        # Check active sessions first (real-time data)
        if session_id in self.active_sessions:
            return self.active_sessions[session_id]
        
        # Fall back to database
        session = BusinessSearchSession.query.get(session_id)
        if not session:
            return {'status': 'not_found', 'error': 'Session not found'}
        
        return {
            'status': session.status,
            'progress': session.progress,
            'current_location': session.current_location,
            'total_businesses': session.total_businesses_found,
            'processing_time': session.processing_time
        }
    
    def get_session_results(self, session_id: int, user_id: int) -> Dict:
        """
        Get results from a completed search session
        
        Args:
            session_id: ID of search session
            user_id: ID of user (for security)
        
        Returns:
            Dictionary with session results
        """
        session = BusinessSearchSession.query.filter_by(
            id=session_id, user_id=user_id
        ).first()
        
        if not session:
            logger.error(f"Session {session_id} not found for user {user_id}")
            return {'error': 'Session not found or access denied'}
        
        # Check if this is a bulk search with child sessions
        child_sessions = BusinessSearchSession.query.filter_by(parent_session_id=session_id).all()
        
        if child_sessions:
            # This is a bulk search with separate keyword sessions
            keyword_results = []
            total_businesses = 0
            
            for child_session in child_sessions:
                # Get businesses for this child session
                businesses = BusinessData.query.filter_by(session_id=child_session.id).all()
                business_dicts = [business.to_dict() for business in businesses]
                
                keyword_results.append({
                    'session_id': child_session.id,
                    'keyword': child_session.keywords,
                    'url_count': len(businesses),
                    'businesses': business_dicts,
                    'processing_time': child_session.processing_time,
                    'status': child_session.status
                })
                
                total_businesses += len(businesses)
            
            logger.info(f"Found {len(child_sessions)} separate keyword sessions for parent session {session_id}")
            logger.info(f"Total URLs across all keywords: {total_businesses}")
            
            # Also group all businesses by city for template compatibility
            businesses_by_city = {}
            all_businesses = []
            for keyword_result in keyword_results:
                for business in keyword_result['businesses']:
                    all_businesses.append(business)
                    city = business.get('city', 'Unknown')
                    if city not in businesses_by_city:
                        businesses_by_city[city] = []
                    businesses_by_city[city].append(business)
            
            return {
                'session': {
                    'id': session.id,
                    'keywords': session.keywords,
                    'cities': session.get_cities_list(),
                    'status': session.status,
                    'total_businesses_found': session.total_businesses_found,
                    'processing_time': session.processing_time,
                    'created_at': session.created_at.isoformat() if session.created_at else None,
                    'completed_at': session.completed_at.isoformat() if session.completed_at else None
                },
                'is_bulk_search': True,
                'keyword_results': keyword_results,
                'businesses_by_city': businesses_by_city,  # Add this for template compatibility
                'total_businesses': total_businesses
            }
        
        else:
            # Single keyword search - original behavior
            businesses = BusinessData.query.filter_by(session_id=session_id).all()
            logger.info(f"Found {len(businesses)} businesses in database for session {session_id}")
            
            # Group businesses by city
            businesses_by_city = {}
            for business in businesses:
                city = business.city
                if city not in businesses_by_city:
                    businesses_by_city[city] = []
                businesses_by_city[city].append(business.to_dict())
                
            logger.info(f"Businesses grouped by city: {list(businesses_by_city.keys())}")
            logger.info(f"Total businesses by city: {sum(len(city_businesses) for city_businesses in businesses_by_city.values())}")
            
            return {
                'session': {
                    'id': session.id,
                    'keywords': session.keywords,
                    'cities': session.get_cities_list(),
                    'status': session.status,
                    'total_businesses_found': session.total_businesses_found,
                    'processing_time': session.processing_time,
                    'created_at': session.created_at.isoformat() if session.created_at else None,
                    'completed_at': session.completed_at.isoformat() if session.completed_at else None
                },
                'is_bulk_search': False,
                'businesses_by_city': businesses_by_city,
                'total_businesses': len(businesses)
            }

# Global service instance
business_search_service = BusinessSearchService()