"""
Business Search Service for Google Maps Places integration via Serper.dev
"""
import time
import threading
from typing import Dict, List, Optional
from datetime import datetime
from models import db, BusinessSearchSession, BusinessData, User
from api_rotation import APIRotationManager
from serper_api_utils import search_places_serper, extract_email_from_website
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
                        
                        # Search businesses in this city page by page
                        businesses = self._search_businesses_paginated(
                            session.keywords, city, session.max_results_per_city, session_id
                        )
                        
                        # Save businesses page by page with real-time updates
                        saved_count = 0
                        for i, business_data in enumerate(businesses, 1):
                            try:
                                business = BusinessData()
                                business.session_id = session.id
                                business.user_id = session.user_id
                                business.keywords_searched = session.keywords
                                business.city = city
                                
                                # Map business data
                                business.name = business_data.get('name', '')
                                business.address = business_data.get('address', '')
                                business.phone = business_data.get('phone', '')
                                business.website = business_data.get('website', '')
                                business.rating = business_data.get('rating')
                                business.user_ratings_total = business_data.get('user_ratings_total')
                                business.price_level = business_data.get('price_level')
                                business.business_status = business_data.get('business_status', '')
                                business.latitude = business_data.get('latitude')
                                business.longitude = business_data.get('longitude')
                                business.place_id = business_data.get('place_id', '')
                                
                                # Set JSON fields safely
                                try:
                                    business.set_types_list(business_data.get('types', []))
                                except:
                                    business.types = json.dumps([])
                                    
                                try:
                                    business.opening_hours = json.dumps(business_data.get('opening_hours', []))
                                except:
                                    business.opening_hours = json.dumps([])
                                
                                # Try to extract email from website
                                try:
                                    if business.website:
                                        business.email = extract_email_from_website(business.website)
                                except:
                                    business.email = None
                                
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
            # Search using Serper.dev Places API
            result = search_places_serper(
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
            
            businesses = result.get('places', [])
            
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
        
        # Get all businesses found in this session
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
            'businesses_by_city': businesses_by_city,
            'total_businesses': len(businesses)
        }

# Global service instance
business_search_service = BusinessSearchService()