"""
Background scheduler for automatic API credit monitoring and updates
"""
import logging
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APICreditsScheduler:
    def __init__(self, app=None):
        self.app = app
        self.scheduler = BackgroundScheduler()
        self.is_running = False
        self.refresh_interval_minutes = 15  # Default: every 15 minutes
        self.last_refresh = None
        self.refresh_count = 0
        self.error_count = 0
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the scheduler with Flask app context"""
        self.app = app
        
        # Register shutdown handler
        atexit.register(lambda: self.shutdown())
        
        # Start scheduler
        self.start()
    
    def start(self):
        """Start the background scheduler"""
        if not self.is_running:
            try:
                self.scheduler.start()
                self.is_running = True
                logger.info("🟢 API Credits Scheduler started successfully")
                
                # Schedule the automatic refresh job
                self.schedule_credit_refresh()
                
            except Exception as e:
                logger.error(f"❌ Failed to start scheduler: {str(e)}")
                self.is_running = False
    
    def stop(self):
        """Stop the background scheduler"""
        if self.is_running:
            try:
                self.scheduler.shutdown()
                self.is_running = False
                logger.info("🔴 API Credits Scheduler stopped")
            except Exception as e:
                logger.error(f"❌ Error stopping scheduler: {str(e)}")
    
    def shutdown(self):
        """Clean shutdown of scheduler"""
        if self.scheduler and self.scheduler.running:
            self.scheduler.shutdown()
    
    def schedule_credit_refresh(self):
        """Schedule the automatic credit refresh job"""
        if not self.is_running:
            return False
            
        try:
            # Remove existing job if it exists
            if self.scheduler.get_job('auto_credit_refresh'):
                self.scheduler.remove_job('auto_credit_refresh')
            
            # Add new job with current interval
            self.scheduler.add_job(
                func=self.refresh_all_api_credits,
                trigger=IntervalTrigger(minutes=self.refresh_interval_minutes),
                id='auto_credit_refresh',
                name='Automatic API Credits Refresh',
                replace_existing=True
            )
            
            logger.info(f"📅 Scheduled automatic credit refresh every {self.refresh_interval_minutes} minutes")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to schedule credit refresh: {str(e)}")
            return False
    
    def refresh_all_api_credits(self):
        """Main function to refresh all active API key credits"""
        if not self.app:
            logger.error("❌ No Flask app context available")
            return
        
        with self.app.app_context():
            try:
                from models import db, APIKey, APIKeyStatus, SystemLog
                from serper_api_utils import bulk_check_all_keys
                
                logger.info("🔄 Starting automatic API credits refresh...")
                
                # Get all active API keys
                api_keys = APIKey.query.filter_by(status=APIKeyStatus.ACTIVE).all()
                
                if not api_keys:
                    logger.info("ℹ️ No active API keys found for refresh")
                    return
                
                # Check live credits for all keys
                live_data = bulk_check_all_keys(api_keys)
                
                updated_count = 0
                low_credit_alerts = []
                
                # Update database with live data
                for key_detail in live_data['key_details']:
                    if key_detail['is_live']:
                        api_key = APIKey.query.filter_by(key_name=key_detail['name']).first()
                        if api_key:
                            # Update credits
                            old_remaining = api_key.remaining_credits
                            api_key.total_credits = key_detail['total_credits']
                            actual_used = key_detail['total_credits'] - key_detail['credits_left']
                            api_key.credits_used = actual_used
                            api_key.last_credit_check = datetime.utcnow()
                            updated_count += 1
                            
                            # Check for low credits
                            if key_detail['credits_left'] < 500:
                                low_credit_alerts.append({
                                    'name': key_detail['name'],
                                    'credits_left': key_detail['credits_left'],
                                    'was_low_before': old_remaining < 500
                                })
                            
                            # AUTO-ACTIVATE: Keys with >2000 credits (monthly renewal detected)
                            if key_detail['credits_left'] > 2000 and api_key.status == APIKeyStatus.INACTIVE:
                                api_key.status = APIKeyStatus.ACTIVE
                                logger.info(f"🔄 AUTO-ACTIVATED {api_key.key_name}: {key_detail['credits_left']} credits (monthly renewal detected)")
                            
                            # AUTO-DEACTIVATE: Keys with 0 credits (completely unusable)
                            elif key_detail['credits_left'] == 0 and api_key.status == APIKeyStatus.ACTIVE:
                                api_key.status = APIKeyStatus.INACTIVE
                                logger.info(f"🔄 AUTO-DEACTIVATED {api_key.key_name}: 0 credits (unusable)")
                            
                            logger.info(f"✅ Updated {api_key.key_name}: {key_detail['credits_left']} credits remaining")
                
                # Commit all changes
                db.session.commit()
                
                # Log summary
                self.last_refresh = datetime.utcnow()
                self.refresh_count += 1
                
                # Create system log entry
                log_message = f"Auto-refresh completed: {updated_count}/{len(api_keys)} keys updated"
                if low_credit_alerts:
                    log_message += f", {len(low_credit_alerts)} low credit alerts"
                
                from models import SystemLog, db
                system_log = SystemLog()
                system_log.level = 'info'
                system_log.message = log_message
                db.session.add(system_log)
                db.session.commit()
                
                logger.info(f"✅ {log_message}")
                
                # Handle low credit alerts
                if low_credit_alerts:
                    self._handle_low_credit_alerts(low_credit_alerts)
                
            except Exception as e:
                self.error_count += 1
                error_msg = f"Auto credit refresh failed: {str(e)}"
                logger.error(f"❌ {error_msg}")
                
                # Log error to database if possible
                try:
                    from models import SystemLog, db
                    system_log = SystemLog()
                    system_log.level = 'error'
                    system_log.message = error_msg
                    db.session.add(system_log)
                    db.session.commit()
                except:
                    pass  # Don't let logging errors crash the refresh
    
    def _handle_low_credit_alerts(self, low_credit_alerts):
        """Handle low credit alerts by logging warnings"""
        for alert in low_credit_alerts:
            if not alert['was_low_before']:
                # This is a new low credit situation
                logger.warning(f"🚨 NEW LOW CREDIT ALERT: {alert['name']} has {alert['credits_left']} credits remaining!")
            else:
                # Credit was already low, just update
                logger.warning(f"⚠️ CONTINUING LOW CREDITS: {alert['name']} has {alert['credits_left']} credits remaining")
    
    def set_refresh_interval(self, minutes):
        """Update the refresh interval and reschedule"""
        if minutes < 1 or minutes > 1440:  # 1 minute to 24 hours
            raise ValueError("Refresh interval must be between 1 and 1440 minutes")
        
        old_interval = self.refresh_interval_minutes
        self.refresh_interval_minutes = minutes
        
        if self.is_running:
            success = self.schedule_credit_refresh()
            if success:
                logger.info(f"🔄 Refresh interval changed from {old_interval} to {minutes} minutes")
                return True
            else:
                # Revert on failure
                self.refresh_interval_minutes = old_interval
                return False
        return True
    
    def get_status(self):
        """Get current scheduler status"""
        return {
            'is_running': self.is_running,
            'refresh_interval_minutes': self.refresh_interval_minutes,
            'last_refresh': self.last_refresh,
            'refresh_count': self.refresh_count,
            'error_count': self.error_count,
            'next_refresh': self._get_next_refresh_time()
        }
    
    def _get_next_refresh_time(self):
        """Calculate next refresh time"""
        if not self.is_running or not self.last_refresh:
            return None
        
        return self.last_refresh + timedelta(minutes=self.refresh_interval_minutes)
    
    def force_refresh(self):
        """Force an immediate credit refresh"""
        if not self.is_running:
            return False, "Scheduler not running"
        
        try:
            self.refresh_all_api_credits()
            return True, "Force refresh completed successfully"
        except Exception as e:
            return False, f"Force refresh failed: {str(e)}"

# Global scheduler instance
credits_scheduler = APICreditsScheduler()