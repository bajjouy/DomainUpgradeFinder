from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response, current_app, make_response
from flask_login import login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import stripe
import json
import io
import pandas as pd
from datetime import datetime
import tempfile
import logging

# Local imports
from models import db, User, APIKey, CoinTransaction, SearchHistory, SearchSession, PricingPackage, SystemLog, UserRole, APIKeyStatus, TransactionStatus, PaymentMethod, PaymentMethodType, SMTPSettings, ContactForm
from config import Config
from auth_utils import bcrypt, login_manager, admin_required, client_required, hash_password, check_password
from api_rotation import EnhancedDomainAnalyzer
from utils import parse_domain_list
from paypal_integration import PayPalAPI
from background_scheduler import credits_scheduler
from security_utils import (
    validate_form_data, sanitize_input, secure_headers, 
    log_security_event, rate_limit_exceeded
)
from cache_manager import cache_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    # Initialize security extensions
    csrf = CSRFProtect(app)
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["1000 per hour", "100 per minute"],
        on_breach=rate_limit_exceeded
    )
    
    migrate = Migrate(app, db)
    
    # Configure Stripe
    stripe.api_key = app.config['STRIPE_SECRET_KEY']
    
    # PayPal configuration is handled in config.py
    # Validate that PayPal credentials are properly configured
    if not app.config.get('PAYPAL_CLIENT_ID') or not app.config.get('PAYPAL_CLIENT_SECRET'):
        logger.warning("PayPal credentials not configured - PayPal payments will be disabled")
    
    # Initialize domain analyzer
    app.domain_analyzer = EnhancedDomainAnalyzer()
    
    # Initialize background scheduler for automatic credit monitoring
    credits_scheduler.init_app(app)
    
    # Create tables
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(role=UserRole.ADMIN).first()
        if not admin:
            admin = User()
            admin.email = 'admin@example.com'
            admin.password_hash = hash_password('admin123')
            admin.role = UserRole.ADMIN
            admin.coins = 1000  # Give admin some coins
            db.session.add(admin)
        
        # Create default pricing packages
        if not PricingPackage.query.first():
            packages = [
                PricingPackage(name='Starter Pack', coins=100, price_cents=1000),  # $10
                PricingPackage(name='Professional Pack', coins=500, price_cents=4000),  # $40
                PricingPackage(name='Enterprise Pack', coins=1000, price_cents=7500),  # $75
            ]
            for package in packages:
                db.session.add(package)
        
        db.session.commit()
    
    # Routes
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            if current_user.role == UserRole.ADMIN:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('client_dashboard'))
        # Show the professional home page with pricing for non-authenticated users
        pricing_packages = PricingPackage.query.filter_by(is_active=True).order_by(PricingPackage.coins).all()
        return render_template('home.html', pricing_packages=pricing_packages)
    
    @app.route('/home')
    def home():
        # Get pricing packages for the homepage
        pricing_packages = PricingPackage.query.filter_by(is_active=True).order_by(PricingPackage.coins).all()
        return render_template('home.html', pricing_packages=pricing_packages)
    
    @app.route('/about-us')
    def about_us():
        return render_template('about_us.html')
    
    # Authentication routes
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("10 per minute")  # Prevent brute force attacks
    @secure_headers
    def login():
        if request.method == 'POST':
            # Input validation and sanitization
            email = sanitize_input(request.form.get('email', ''))
            password = request.form.get('password', '')
            captcha = request.form.get('captcha', '').upper()
            captcha_answer = request.form.get('captcha_answer', '').upper()
            
            # Validate inputs
            validation_rules = {
                'email': {'required': True, 'type': 'email'},
                'password': {'required': True, 'type': 'safe_string', 'max_length': 200}
            }
            
            is_valid, errors = validate_form_data({
                'email': email,
                'password': password
            }, validation_rules)
            
            if not is_valid:
                for error in errors:
                    flash(error, 'error')
                log_security_event('invalid_login_attempt', f'Validation failed: {", ".join(errors)}')
                return render_template('login.html')
            
            # Validate captcha
            if captcha != captcha_answer:
                flash('Invalid security code. Please try again.', 'error')
                log_security_event('captcha_failure', f'Failed captcha for email: {email}')
                return render_template('login.html')
            
            user = User.query.filter_by(email=email).first()
            
            if user and check_password(user.password_hash, password):
                try:
                    login_user(user)
                    user.last_login = datetime.utcnow()
                    db.session.commit()
                    
                    # Log the successful login (with error handling)
                    try:
                        log_security_event('successful_login', f'User logged in: {email}', user.id)
                    except Exception as log_error:
                        print(f"Warning: Failed to log security event: {log_error}")
                    
                    # Refresh user object to avoid stale session issues
                    db.session.refresh(user)
                    
                    if user.role == UserRole.ADMIN:
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('client_dashboard'))
                        
                except Exception as e:
                    # Rollback the session if any error occurs
                    db.session.rollback()
                    print(f"Login error: {e}")
                    flash('Login failed due to a system error. Please try again.', 'error')
                    return render_template('login.html')
            else:
                flash('Invalid email or password', 'error')
                # Log failed login attempt (with error handling)
                try:
                    log_security_event('failed_login', f'Failed login attempt for email: {email}')
                except Exception as log_error:
                    print(f"Warning: Failed to log failed login event: {log_error}")
        
        return render_template('login.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return render_template('register.html')
            
            user = User()
            user.email = email
            user.password_hash = hash_password(password)
            user.role = UserRole.CLIENT
            user.coins = Config.FREE_TRIAL_COINS  # Free trial coins
            
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email
            try:
                from email_service import email_service
                email_service.send_welcome_email(user.email, user.email.split('@')[0])
            except Exception as e:
                print(f"Failed to send welcome email: {e}")
            
            login_user(user)
            flash(f'Account created! You have {Config.FREE_TRIAL_COINS} free trial coins.', 'success')
            return redirect(url_for('client_dashboard'))
        
        return render_template('register.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out', 'info')
        return redirect(url_for('index'))
    
    # Admin Dashboard Routes
    @app.route('/admin')
    @admin_required
    def admin_dashboard():
        # Get statistics
        total_users = User.query.filter_by(role=UserRole.CLIENT).count()
        total_searches = SearchHistory.query.count()
        total_revenue = db.session.query(db.func.sum(CoinTransaction.amount * 0.1)).filter(
            CoinTransaction.transaction_type == 'purchase',
            CoinTransaction.status == TransactionStatus.COMPLETED
        ).scalar() or 0
        
        # Get API key stats with credit monitoring
        api_keys = APIKey.query.all()
        
        # Get live credit data from Serper API
        from serper_api_utils import bulk_check_all_keys
        live_credit_data = bulk_check_all_keys(api_keys)
        
        # Use live data if available, otherwise fall back to database
        if live_credit_data['live_data_available']:
            total_remaining = live_credit_data['total_live_remaining']
            total_credits = live_credit_data['total_live_credits']
            total_used = live_credit_data['total_live_used']
            is_live_data = True
        else:
            # Fallback to database values
            total_credits = sum(k.total_credits for k in api_keys if k.status == APIKeyStatus.ACTIVE)
            total_used = sum(k.credits_used for k in api_keys if k.status == APIKeyStatus.ACTIVE)
            total_remaining = total_credits - total_used
            is_live_data = False
            
        low_credit_keys = [k for k in api_keys if k.is_low_credits and k.status == APIKeyStatus.ACTIVE]
        
        # Recent activity
        recent_searches = SearchHistory.query.order_by(SearchHistory.created_at.desc()).limit(10).all()
        recent_users = User.query.filter_by(role=UserRole.CLIENT).order_by(User.created_at.desc()).limit(10).all()
        
        return render_template('admin/dashboard.html',
                             total_users=total_users,
                             total_searches=total_searches,
                             total_revenue=total_revenue,
                             api_keys=api_keys,
                             low_credit_keys=low_credit_keys,
                             total_credits=total_credits,
                             total_used=total_used,
                             total_remaining=total_remaining,
                             live_credit_data=live_credit_data,
                             is_live_data=is_live_data,
                             recent_searches=recent_searches,
                             recent_users=recent_users)
    
    @app.route('/admin/api-credits')
    @admin_required
    def admin_api_credits():
        api_keys = APIKey.query.all()
        
        # Calculate summary statistics
        total_keys = len(api_keys)
        active_keys = [k for k in api_keys if k.status == APIKeyStatus.ACTIVE]
        low_credit_keys = [k for k in active_keys if k.is_low_credits]
        
        total_credits = sum(k.total_credits for k in active_keys)
        total_used = sum(k.credits_used for k in active_keys)
        total_remaining = total_credits - total_used
        
        # Sort keys by remaining credits (lowest credits first)
        sorted_keys = sorted(active_keys, key=lambda k: k.remaining_credits, reverse=False)
        
        return render_template('admin/api_credits.html',
                             api_keys=api_keys,
                             sorted_keys=sorted_keys,
                             low_credit_keys=low_credit_keys,
                             total_keys=total_keys,
                             total_credits=total_credits,
                             total_used=total_used,
                             total_remaining=total_remaining)
    
    @app.route('/admin/api-credits/<int:key_id>/update', methods=['POST'])
    @admin_required
    def update_api_credits(key_id):
        api_key = APIKey.query.get_or_404(key_id)
        new_total = int(request.form.get('total_credits', api_key.total_credits))
        
        api_key.total_credits = new_total
        db.session.commit()
        
        flash(f'Credits updated for {api_key.key_name}', 'success')
        return redirect(url_for('admin_api_credits'))
    
    @app.route('/admin/sync-credits', methods=['POST'])
    @admin_required
    def sync_api_credits():
        from serper_api_utils import bulk_check_all_keys
        
        api_keys = APIKey.query.filter_by(status=APIKeyStatus.ACTIVE).all()
        live_data = bulk_check_all_keys(api_keys)
        
        synced_count = 0
        errors = []
        
        # Update database with live credit data
        for key_detail in live_data['key_details']:
            if key_detail['is_live']:
                api_key = APIKey.query.filter_by(key_name=key_detail['name']).first()
                if api_key:
                    # Update total credits from live API
                    api_key.total_credits = key_detail['total_credits']
                    # Calculate actual usage from live data
                    actual_used = key_detail['total_credits'] - key_detail['credits_left']
                    api_key.credits_used = actual_used
                    synced_count += 1
        
        if live_data['errors']:
            errors.extend(live_data['errors'])
            
        db.session.commit()
        
        if synced_count > 0:
            flash(f'✅ Synced {synced_count} API key(s) with live data from Serper', 'success')
        
        if errors:
            flash(f'⚠️ Some keys could not be synced: {"; ".join(errors[:3])}', 'warning')
            
        if synced_count == 0 and not errors:
            flash('ℹ️ No active API keys found to sync', 'info')
            
        return redirect(url_for('admin_dashboard'))
    
    @app.route('/admin/scheduler')
    @admin_required
    def admin_scheduler():
        """Admin page for managing automatic API credit refresh scheduler"""
        status = credits_scheduler.get_status()
        
        # Get recent system logs related to scheduler
        from models import SystemLog
        scheduler_logs = SystemLog.query.filter(
            SystemLog.message.like('%refresh%')
        ).order_by(SystemLog.created_at.desc()).limit(20).all()
        
        return render_template('admin/scheduler.html', 
                             status=status, 
                             logs=scheduler_logs)
    
    @app.route('/admin/scheduler/start', methods=['POST'])
    @admin_required
    def start_scheduler():
        """Start the automatic credit refresh scheduler"""
        if not credits_scheduler.is_running:
            credits_scheduler.start()
            flash('✅ Automatic credit refresh scheduler started', 'success')
        else:
            flash('ℹ️ Scheduler is already running', 'info')
        return redirect(url_for('admin_scheduler'))
    
    @app.route('/admin/scheduler/stop', methods=['POST'])
    @admin_required
    def stop_scheduler():
        """Stop the automatic credit refresh scheduler"""
        if credits_scheduler.is_running:
            credits_scheduler.stop()
            flash('⏹️ Automatic credit refresh scheduler stopped', 'warning')
        else:
            flash('ℹ️ Scheduler is already stopped', 'info')
        return redirect(url_for('admin_scheduler'))
    
    @app.route('/admin/scheduler/force-refresh', methods=['POST'])
    @admin_required
    def force_scheduler_refresh():
        """Force an immediate credit refresh"""
        success, message = credits_scheduler.force_refresh()
        if success:
            flash(f'✅ {message}', 'success')
        else:
            flash(f'❌ {message}', 'error')
        return redirect(url_for('admin_scheduler'))
    
    @app.route('/admin/scheduler/set-interval', methods=['POST'])
    @admin_required
    def set_scheduler_interval():
        """Update the scheduler refresh interval"""
        try:
            interval = int(request.form.get('interval', 15))
            if interval < 5 or interval > 1440:
                flash('❌ Interval must be between 5 and 1440 minutes', 'error')
                return redirect(url_for('admin_scheduler'))
            
            success = credits_scheduler.set_refresh_interval(interval)
            if success:
                flash(f'✅ Refresh interval updated to {interval} minutes', 'success')
            else:
                flash('❌ Failed to update refresh interval', 'error')
                
        except (ValueError, TypeError):
            flash('❌ Invalid interval value', 'error')
            
        return redirect(url_for('admin_scheduler'))
    
    @app.route('/admin/api-credits/<int:key_id>/check-live', methods=['POST'])
    @admin_required
    def check_single_api_live(key_id):
        from serper_api_utils import check_serper_credits
        
        api_key = APIKey.query.get_or_404(key_id)
        result = check_serper_credits(api_key.key_value)
        
        # Update database with live data if successful
        if not result.get('error') and result.get('credits_left') is not None:
            api_key.total_credits = result['total_credits']
            actual_used = result['total_credits'] - result['credits_left']
            api_key.credits_used = actual_used
            api_key.last_credit_check = datetime.utcnow()
            db.session.commit()
            
            # Add sync confirmation to result
            result['database_synced'] = True
        else:
            result['database_synced'] = False
        
        return jsonify(result)
    
    @app.route('/admin/cache')
    @admin_required
    @secure_headers
    def admin_cache_management():
        """Admin cache management interface"""
        cache_stats = cache_manager.get_cache_stats()
        cache_health = cache_manager.health_check()
        
        return render_template('admin/cache_management.html', 
                             cache_stats=cache_stats,
                             cache_health=cache_health)
    
    @app.route('/admin/cache/clear', methods=['POST'])
    @admin_required
    @limiter.limit("5 per minute")
    def admin_clear_cache():
        """Clear all cache entries"""
        try:
            result = cache_manager.clear_all_cache()
            flash(f"Cache cleared successfully! {result['entries_cleared']} entries removed.", 'success')
            log_security_event('cache_cleared', f"Admin {current_user.id} cleared all cache", current_user.id)
        except Exception as e:
            flash(f"Error clearing cache: {str(e)}", 'error')
            logger.error(f"Cache clear failed: {str(e)}")
        
        return redirect(url_for('admin_cache_management'))
    
    @app.route('/api/cache/stats')
    @admin_required
    @secure_headers
    def api_cache_stats():
        """API endpoint for cache statistics"""
        return jsonify(cache_manager.get_cache_stats())
    
    @app.route('/api/health/cache')
    @admin_required 
    @secure_headers
    def api_cache_health():
        """API endpoint for cache health check"""
        return jsonify(cache_manager.health_check())
    
    @app.route('/api/health')
    @limiter.limit("30 per minute")
    @secure_headers
    def api_health_check():
        """System health check endpoint"""
        try:
            # Check database connection
            db_healthy = True
            try:
                db.session.execute('SELECT 1')
            except Exception:
                db_healthy = False
            
            # Check API keys status
            active_keys = APIKey.query.filter_by(status=APIKeyStatus.ACTIVE).count()
            total_keys = APIKey.query.count()
            
            # Basic cache health
            cache_stats = cache_manager.get_cache_stats()
            
            health_status = {
                'status': 'healthy' if db_healthy and active_keys > 0 else 'degraded',
                'timestamp': datetime.utcnow().isoformat(),
                'components': {
                    'database': 'healthy' if db_healthy else 'unhealthy',
                    'api_keys': f'{active_keys}/{total_keys} active',
                    'cache': {
                        'status': 'healthy',
                        'hit_rate': f"{cache_stats['hit_rate']}%",
                        'entries': cache_stats['entries']
                    },
                    'scheduler': 'healthy' if credits_scheduler.is_running else 'stopped'
                },
                'version': '1.0.0'
            }
            
            status_code = 200 if health_status['status'] == 'healthy' else 503
            return jsonify(health_status), status_code
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 503
    
    @app.route('/admin/api-keys')
    @admin_required
    def admin_api_keys():
        api_keys = APIKey.query.all()
        return render_template('admin/api_keys.html', api_keys=api_keys)
    
    @app.route('/admin/api-keys/add', methods=['POST'])
    @admin_required
    def add_api_key():
        from serper_api_utils import check_serper_credits
        
        key_name = request.form.get('key_name')
        key_value = request.form.get('key_value')
        daily_limit = int(request.form.get('daily_limit', 2500))
        total_credits = int(request.form.get('total_credits', 2500))
        
        # Validate API key before adding
        validation_result = check_serper_credits(key_value)
        
        if validation_result.get('error'):
            flash(f'❌ API key validation failed: {validation_result["error"]}', 'error')
            return redirect(url_for('admin_api_keys'))
        
        # Check if key already exists
        existing_key = APIKey.query.filter_by(key_value=key_value).first()
        if existing_key:
            flash('❌ API key already exists in the system', 'error')
            return redirect(url_for('admin_api_keys'))
        
        # Use live data from validation for accurate credits
        live_total_credits = validation_result.get('total_credits', total_credits)
        live_credits_left = validation_result.get('credits_left', total_credits)
        live_credits_used = live_total_credits - live_credits_left
        
        api_key = APIKey()
        api_key.key_name = key_name
        api_key.key_value = key_value
        api_key.daily_limit = daily_limit
        api_key.total_credits = live_total_credits
        api_key.credits_used = live_credits_used
        api_key.last_credit_check = datetime.utcnow()
        api_key.status = APIKeyStatus.ACTIVE
        
        db.session.add(api_key)
        db.session.commit()
        
        flash(f'✅ API key added successfully with {live_credits_left} credits available', 'success')
        return redirect(url_for('admin_api_keys'))
    
    @app.route('/admin/api-keys/bulk-add', methods=['POST'])
    @admin_required
    def bulk_add_api_keys():
        """Bulk add API keys from textarea input"""
        bulk_keys_text = request.form.get('bulk_keys', '').strip()
        bulk_daily_limit = int(request.form.get('bulk_daily_limit', 2500))
        bulk_total_credits = int(request.form.get('bulk_total_credits', 2500))
        
        if not bulk_keys_text:
            flash('❌ Please provide API keys to import', 'error')
            return redirect(url_for('admin_api_keys'))
        
        # Split by lines and clean up each key
        api_keys_list = []
        for line in bulk_keys_text.split('\n'):
            key = line.strip()
            if key:  # Skip empty lines
                api_keys_list.append(key)
        
        if not api_keys_list:
            flash('❌ No valid API keys found', 'error')
            return redirect(url_for('admin_api_keys'))
        
        # Get current highest api number for naming
        existing_api_names = [key.key_name for key in APIKey.query.all() if key.key_name.startswith('api')]
        max_num = 0
        for name in existing_api_names:
            try:
                if name.startswith('api') and name[3:].isdigit():
                    num = int(name[3:])
                    max_num = max(max_num, num)
            except:
                continue
        
        added_count = 0
        skipped_count = 0
        errors = []
        
        validation_failed_count = 0
        
        for i, key_value in enumerate(api_keys_list):
            try:
                # Generate sequential name
                key_name = f'api{max_num + i + 1}'
                
                # Check if key already exists
                existing_key = APIKey.query.filter_by(key_value=key_value).first()
                if existing_key:
                    skipped_count += 1
                    errors.append(f'{key_name}: Already exists')
                    continue
                
                # Validate API key before adding
                from serper_api_utils import check_serper_credits
                print(f"DEBUG: Validating API key {key_name}...")
                validation_result = check_serper_credits(key_value)
                
                if validation_result.get('error'):
                    validation_failed_count += 1
                    errors.append(f'{key_name}: Validation failed - {validation_result["error"]}')
                    continue
                
                # Use live data from validation for accurate credits
                live_total_credits = validation_result.get('total_credits', bulk_total_credits)
                live_credits_left = validation_result.get('credits_left', bulk_total_credits)
                live_credits_used = live_total_credits - live_credits_left
                
                # Create new API key with validated data
                api_key = APIKey()
                api_key.key_name = key_name
                api_key.key_value = key_value
                api_key.daily_limit = bulk_daily_limit
                api_key.total_credits = live_total_credits
                api_key.credits_used = live_credits_used
                api_key.last_credit_check = datetime.utcnow()
                api_key.status = APIKeyStatus.ACTIVE
                
                db.session.add(api_key)
                added_count += 1
                print(f"DEBUG: Successfully validated and added {key_name} with {live_credits_left} credits")
                
            except Exception as e:
                errors.append(f'Key {i+1}: Unexpected error - {str(e)}')
        
        try:
            db.session.commit()
            
            # Flash comprehensive summary
            if added_count > 0:
                flash(f'✅ Successfully added {added_count} working API keys', 'success')
            
            if skipped_count > 0:
                flash(f'⚠️ Skipped {skipped_count} duplicate keys', 'warning')
                
            if validation_failed_count > 0:
                flash(f'❌ Failed validation for {validation_failed_count} keys', 'error')
            
            # Show detailed errors if any
            if errors:
                flash('Detailed results:', 'info')
                for error in errors[:10]:  # Limit to first 10 errors
                    flash(f'• {error}', 'warning')
                if len(errors) > 10:
                    flash(f'• ... and {len(errors) - 10} more errors', 'warning')
                
        except Exception as e:
            db.session.rollback()
            flash(f'❌ Database error: {str(e)}', 'error')
        
        return redirect(url_for('admin_api_keys'))
    
    @app.route('/admin/api-keys/<int:key_id>/toggle')
    @admin_required
    def toggle_api_key(key_id):
        api_key = APIKey.query.get_or_404(key_id)
        
        if api_key.status == APIKeyStatus.ACTIVE:
            api_key.status = APIKeyStatus.INACTIVE
        else:
            api_key.status = APIKeyStatus.ACTIVE
        
        db.session.commit()
        flash('API key status updated', 'success')
        return redirect(url_for('admin_api_keys'))
    
    @app.route('/admin/api-keys/<int:key_id>/delete', methods=['POST'])
    @admin_required
    def delete_api_key(key_id):
        api_key = APIKey.query.get_or_404(key_id)
        key_name = api_key.key_name
        
        # Check if this API key is currently being used in active searches
        # We could add additional checks here if needed
        
        db.session.delete(api_key)
        db.session.commit()
        
        flash(f'✅ API key "{key_name}" has been deleted permanently', 'success')
        return redirect(url_for('admin_api_keys'))
    
    @app.route('/admin/users')
    @admin_required
    def admin_users():
        users = User.query.filter_by(role=UserRole.CLIENT).all()
        return render_template('admin/users.html', users=users)
    
    @app.route('/admin/users/<int:user_id>/coins', methods=['POST'])
    @admin_required
    def adjust_user_coins(user_id):
        from security_utils import validate_coin_amount
        
        user = User.query.get_or_404(user_id)
        amount_str = request.form.get('amount', '').strip()
        reason = request.form.get('reason', 'Admin adjustment')
        
        # Validate input is not empty
        if not amount_str:
            flash('Please enter a coin amount', 'error')
            return redirect(url_for('admin_users'))
        
        try:
            amount = int(amount_str)
        except ValueError:
            flash('Invalid coin amount - please enter a number', 'error')
            return redirect(url_for('admin_users'))
        
        # Check for reasonable limits (admin can do more than regular validation)
        if abs(amount) > 1000000:  # 1 million coin limit
            flash('Amount too large - maximum 1,000,000 coins per adjustment', 'error')
            return redirect(url_for('admin_users'))
        
        if amount == 0:
            flash('Amount cannot be zero', 'error')
            return redirect(url_for('admin_users'))
        
        # Check if deduction would result in negative balance
        if amount < 0 and user.coins + amount < 0:
            flash(f'Cannot deduct {abs(amount)} coins - user only has {user.coins} coins', 'error')
            return redirect(url_for('admin_users'))
        
        # Apply the adjustment
        if amount > 0:
            user.add_coins(amount, 'admin_adjustment')
            flash(f'Added {amount} coins to {user.email}', 'success')
        else:
            user.deduct_coins(abs(amount), 'admin_adjustment')
            flash(f'Deducted {abs(amount)} coins from {user.email}', 'success')
        
        db.session.commit()
        
        # Send email notification to user
        try:
            from email_service import email_service
            email_service.send_coin_adjustment_notification(
                user.email, 
                user.email.split('@')[0],  # Use email prefix as name
                amount, 
                reason, 
                user.coins
            )
        except Exception as e:
            print(f"Failed to send coin adjustment email: {e}")
        
        return redirect(url_for('admin_users'))
    
    @app.route('/admin/pricing')
    @admin_required
    def admin_pricing():
        packages = PricingPackage.query.all()
        return render_template('admin/pricing.html', packages=packages)
    
    @app.route('/admin/pricing/add', methods=['POST'])
    @admin_required
    def add_pricing_package():
        name = request.form.get('name')
        coins = int(request.form.get('coins'))
        price_cents = int(float(request.form.get('price')) * 100)
        
        package = PricingPackage()
        package.name = name
        package.coins = coins
        package.price_cents = price_cents
        
        db.session.add(package)
        db.session.commit()
        
        flash('Pricing package added', 'success')
        return redirect(url_for('admin_pricing'))
    
    @app.route('/admin/pricing/<int:package_id>/toggle')
    @admin_required
    def toggle_pricing_package(package_id):
        package = PricingPackage.query.get_or_404(package_id)
        package.is_active = not package.is_active
        db.session.commit()
        
        status = "activated" if package.is_active else "deactivated"
        flash(f'Package "{package.name}" has been {status}!', 'success')
        return redirect(url_for('admin_pricing'))
    
    @app.route('/admin/pricing/<int:package_id>/delete', methods=['POST'])
    @admin_required
    def delete_pricing_package(package_id):
        package = PricingPackage.query.get_or_404(package_id)
        package_name = package.name
        
        # Check if any users have transactions related to this package
        # We could add this check if needed, but for now we'll allow deletion
        
        db.session.delete(package)
        db.session.commit()
        
        flash(f'Package "{package_name}" has been deleted permanently!', 'success')
        return redirect(url_for('admin_pricing'))
    
    @app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
    @admin_required
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)
        
        # Prevent admin from deleting themselves
        if user.id == current_user.id:
            flash('You cannot delete your own account.', 'error')
            return redirect(url_for('admin_users'))
        
        # Prevent deleting other admin users
        if user.role == UserRole.ADMIN:
            flash('Cannot delete admin users.', 'error')
            return redirect(url_for('admin_users'))
        
        user_email = user.email
        
        # Delete associated records first
        CoinTransaction.query.filter_by(user_id=user_id).delete()
        SearchHistory.query.filter_by(user_id=user_id).delete()
        SearchSession.query.filter_by(user_id=user_id).delete()
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        
        flash(f'User {user_email} has been deleted successfully.', 'success')
        return redirect(url_for('admin_users'))
    
    @app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
    @admin_required
    def toggle_user_status(user_id):
        user = User.query.get_or_404(user_id)
        
        # Prevent admin from deactivating themselves
        if user.id == current_user.id:
            flash('You cannot change your own account status.', 'error')
            return redirect(url_for('admin_users'))
        
        # Prevent changing status of other admin users
        if user.role == UserRole.ADMIN:
            flash('Cannot change admin user status.', 'error')
            return redirect(url_for('admin_users'))
        
        user.user_active = not user.user_active
        db.session.commit()
        
        # Send account status change notification
        try:
            from email_service import email_service
            email_service.send_account_status_change_notification(
                user.email, 
                user.email.split('@')[0], 
                user.user_active
            )
        except Exception as e:
            print(f"Failed to send account status change email: {e}")
        
        status = "activated" if user.user_active else "deactivated"
        flash(f'User {user.email} has been {status}.', 'success')
        return redirect(url_for('admin_users'))
    
    @app.route('/admin/users/<int:user_id>/change-password', methods=['POST'])
    @admin_required
    def change_user_password(user_id):
        user = User.query.get_or_404(user_id)
        new_password = request.form.get('new_password')
        
        if not new_password or len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('admin_users'))
        
        # Hash the new password
        user.password_hash = hash_password(new_password)
        db.session.commit()
        
        # Send password change notification
        try:
            from email_service import email_service
            email_service.send_password_change_notification(
                user.email, 
                user.email.split('@')[0], 
                changed_by_admin=True
            )
        except Exception as e:
            print(f"Failed to send password change email: {e}")
        
        flash(f'Password changed successfully for {user.email}.', 'success')
        return redirect(url_for('admin_users'))
    
    # Client Dashboard Routes
    @app.route('/dashboard')
    @client_required
    def client_dashboard():
        # Get user's search history (recent searches for activity display)
        recent_searches = SearchHistory.query.filter_by(user_id=current_user.id).order_by(
            SearchHistory.created_at.desc()).limit(5).all()
        
        # Get user's transaction history
        recent_transactions = CoinTransaction.query.filter_by(user_id=current_user.id).order_by(
            CoinTransaction.created_at.desc()).limit(5).all()
        
        # Get user's searches from last 24 hours to calculate upkeywords
        from datetime import timedelta
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        recent_search_data = SearchHistory.query.filter(
            SearchHistory.user_id == current_user.id,
            SearchHistory.created_at >= twenty_four_hours_ago
        ).all()
        
        # Calculate upkeywords (keywords with at least 1 upgrade)
        upkeywords_dict = {}
        total_upgrades = 0
        
        for search in recent_search_data:
            results = search.get_results()
            if results:
                keyword = search.keywords
                
                # Track domain duplicates within this keyword to avoid counting same domain multiple times
                domain_tracker = {}
                keyword_upgrade_count = 0
                total_competitors = 0
                
                for result in results:
                    competitor_domain = result.get('Competitor_Domain', '')
                    is_upgrade = result.get('Is_Upgrade', False)
                    
                    if competitor_domain:
                        if competitor_domain not in domain_tracker:
                            domain_tracker[competitor_domain] = {
                                'is_upgrade': is_upgrade,
                                'total_count': 1
                            }
                            total_competitors += 1
                            if is_upgrade:
                                keyword_upgrade_count += 1
                                total_upgrades += 1
                        else:
                            # Domain already exists, just track if it's an upgrade (don't double count)
                            if is_upgrade and not domain_tracker[competitor_domain]['is_upgrade']:
                                domain_tracker[competitor_domain]['is_upgrade'] = True
                                keyword_upgrade_count += 1
                                total_upgrades += 1
                
                # Only include keywords that have upgrades
                if keyword_upgrade_count > 0:
                    if keyword in upkeywords_dict:
                        # Merge with existing data (might have duplicate keywords from different searches)
                        upkeywords_dict[keyword]['upgrade_count'] += keyword_upgrade_count
                        upkeywords_dict[keyword]['total_competitors'] += total_competitors
                    else:
                        upkeywords_dict[keyword] = {
                            'keyword': keyword,
                            'upgrade_count': keyword_upgrade_count,
                            'total_competitors': total_competitors
                        }
        
        # Convert to list and sort by upgrade count (highest first)
        upkeywords = sorted(upkeywords_dict.values(), key=lambda x: x['upgrade_count'], reverse=True)[:10]
        
        return render_template('client/dashboard.html',
                             user=current_user,
                             recent_searches=recent_searches,
                             total_upgrades=total_upgrades,
                             upkeywords=upkeywords)
    
    @app.route('/search', methods=['GET', 'POST'])
    @client_required
    @limiter.limit("50 per hour")  # Limit search requests to prevent abuse
    @secure_headers
    def search():
        if request.method == 'POST':
            # Check if user has enough coins (skip for admin users)
            if current_user.role != UserRole.ADMIN and current_user.coins < 1:
                flash('You need at least 1 coin to perform a search. Please purchase more coins.', 'error')
                return redirect(url_for('buy_coins'))
            
            # Get and validate input
            keywords_input = sanitize_input(request.form.get('keywords', ''))
            max_results = 100  # Use adaptive max_results - start with 100, reduce by 10 if fails
            
            # Validate search input
            validation_rules = {
                'keywords': {'required': True, 'type': 'search_keywords'}
            }
            
            is_valid, errors = validate_form_data({
                'keywords': keywords_input
            }, validation_rules)
            
            if not is_valid:
                for error in errors:
                    flash(error, 'error')
                log_security_event('invalid_search_input', f'User {current_user.id}: {", ".join(errors)}', current_user.id)
                return render_template('client/search.html')
            
            # Parse keywords (one set per line)
            keyword_sets = parse_domain_list(keywords_input)
            
            if not keyword_sets:
                flash('Please enter valid keywords', 'error')
                return render_template('client/search.html')
            
            # Check if user has enough coins for all searches (skip for admin users)
            total_searches = len(keyword_sets)
            if current_user.role != UserRole.ADMIN and current_user.coins < total_searches:
                flash(f'You need {total_searches} coins for this search but only have {current_user.coins} coins.', 'error')
                return redirect(url_for('buy_coins'))
            
            # Check for bulk processing limits
            max_bulk_keywords = 5000  # Configurable limit
            if total_searches > max_bulk_keywords:
                flash(f'Maximum {max_bulk_keywords} keywords allowed per search session. You entered {total_searches} keywords.', 'error')
                return render_template('client/search.html')
            
            # For bulk processing, redirect to processor
            if total_searches > 10:  # Use bulk processing for more than 10 keywords
                # Create search session immediately to avoid large session cookies
                search_session = SearchSession()
                search_session.user_id = current_user.id
                search_session.total_keywords = total_searches
                search_session.keyword_list = keywords_input
                search_session.status = 'pending'
                search_session.max_results = 100  # Store starting max results (will be adaptive)
                
                db.session.add(search_session)
                db.session.commit()
                
                # Store only the session ID (much smaller)
                session['pending_session_id'] = search_session.id
                return redirect(url_for('bulk_search_processor'))
            
            # Regular processing for small searches
            try:
                all_results = []
                
                # Create search session
                search_session = SearchSession()
                search_session.user_id = current_user.id
                search_session.total_keywords = total_searches
                search_session.keyword_list = keywords_input
                search_session.status = 'processing'
                search_session.max_results = 100  # Store starting max results (will be adaptive)
                db.session.add(search_session)
                db.session.flush()
                
                def adaptive_search(keywords):
                    """Try search with reducing max_results: 100, 90, 80, 70, etc."""
                    for attempt_results in range(100, 9, -10):  # 100, 90, 80, 70, 60, 50, 40, 30, 20, 10
                        try:
                            print(f"DEBUG: Trying search with max_results={attempt_results} for keywords: {keywords}")
                            search_start = datetime.utcnow()
                            results, api_key_used = app.domain_analyzer.analyze_keywords(keywords, max_results=attempt_results)
                            search_duration = (datetime.utcnow() - search_start).total_seconds()
                            
                            # If we get results or no error, return success
                            print(f"DEBUG: Search successful with max_results={attempt_results}, found {len(results) if results else 0} results")
                            return results, api_key_used, search_duration, attempt_results
                            
                        except Exception as e:
                            print(f"DEBUG: Search failed with max_results={attempt_results}, error: {str(e)}")
                            if attempt_results <= 10:  # Last attempt
                                raise e  # Re-raise the last error
                            continue  # Try with fewer results
                    
                    # If we get here, all attempts failed
                    raise Exception("All adaptive search attempts failed")

                for keywords in keyword_sets:
                    # Deduct coin for this search (skip for admin users)
                    if current_user.role != UserRole.ADMIN and not current_user.deduct_coins(1, 'search'):
                        flash('Insufficient coins', 'error')
                        break
                    
                    # Perform adaptive search
                    try:
                        results, api_key_used, search_duration, used_max_results = adaptive_search(keywords)
                        print(f"DEBUG: Final search completed with max_results={used_max_results}")
                    except Exception as e:
                        print(f"DEBUG: All adaptive search attempts failed for keywords '{keywords}': {str(e)}")
                        results, api_key_used, search_duration = [], None, 0.0
                    
                    # Save search history linked to session
                    search_history = SearchHistory()
                    search_history.user_id = current_user.id
                    search_history.keywords = keywords
                    search_history.set_results(results)
                    search_history.api_key_used = api_key_used
                    search_history.search_duration = search_duration
                    search_history.session_id = search_session.id
                    
                    db.session.add(search_history)
                    all_results.extend(results)
                
                # Complete the session
                search_session.status = 'completed'
                search_session.progress = 100.0
                search_session.completed_at = datetime.utcnow()
                db.session.commit()
                
                # Always process results, even if empty
                # Group results by keyword for display
                def group_results_by_keyword(results):
                    """Group competitor domains under same keyword as one upgrade opportunity"""
                    grouped = {}
                    for result in results:
                        keyword = result['Keywords']
                        if keyword not in grouped:
                            grouped[keyword] = {
                                'Keywords': keyword,
                                'Competitors': [],
                                'Has_Upgrade': False,
                                'Total_Competitors': 0,
                                'Upgrade_Competitors': 0,
                                'upkeyword': False  # Track if this keyword has upgrades for dashboard
                            }
                        
                        # Add competitor to this keyword group
                        grouped[keyword]['Competitors'].append(result)
                        grouped[keyword]['Total_Competitors'] += 1
                        
                        # Track if this keyword group has any upgrade opportunities
                        if result.get('Is_Upgrade', False):
                            grouped[keyword]['Has_Upgrade'] = True
                            grouped[keyword]['upkeyword'] = True  # Mark as having upgrades
                            grouped[keyword]['Upgrade_Competitors'] += 1
                    
                    return grouped
                
                # Group results and filter for upgrade opportunities
                grouped_results = group_results_by_keyword(all_results) if all_results else {}
                upgrade_groups = {k: v for k, v in grouped_results.items() if v['Has_Upgrade']}
                
                # Store search session ID for downloads (much smaller than full data)
                session['latest_session_id'] = search_session.id
                
                # Calculate counts
                total_count = len(all_results) if all_results else 0
                upgrade_count = len(upgrade_groups)  # Count unique keywords with upgrades, not individual domains
                
                # Update the search session with final statistics
                search_session.total_results = total_count
                search_session.upgrade_results = upgrade_count
                db.session.commit()
                
                # Show success message based on results
                if upgrade_count > 0:
                    flash(f'Search completed! Found {upgrade_count} upgrade opportunities out of {total_count} total results.', 'success')
                elif total_count > 0:
                    flash(f'Search completed! Found {total_count} potential matches but no clear upgrade opportunities.', 'info')
                else:
                    flash('Search completed! No results found for your keywords.', 'warning')
                
                # Always show results page with grouped data
                return render_template('client/search.html', 
                                     show_results=True,
                                     grouped_results=upgrade_groups,
                                     all_results=all_results or [],
                                     total_results=total_count,
                                     upgrade_count=upgrade_count)
                
            except Exception as e:
                flash(f'Search error: {str(e)}', 'error')
                return render_template('client/search.html')
        
        return render_template('client/search.html')
    
    @app.route('/bulk-search-processor')
    @client_required
    def bulk_search_processor():
        session_id = session.get('pending_session_id')
        
        if not session_id:
            flash('Invalid search parameters', 'error')
            return redirect(url_for('search'))
        
        # Get search session from database
        search_session = SearchSession.query.filter_by(
            id=session_id, user_id=current_user.id, status='pending').first()
        
        if not search_session:
            flash('Search session not found or already processed', 'error')
            return redirect(url_for('search'))
        
        # Clear session data
        session.pop('pending_session_id', None)
        
        # Update status to processing
        search_session.status = 'processing'
        db.session.commit()
        
        return render_template('client/bulk_processor.html', session_id=search_session.id)
    
    @app.route('/api/bulk-search/<int:session_id>', methods=['POST'])
    @client_required
    @limiter.limit("20 per hour")  # Stricter limit for bulk processing
    @secure_headers
    @csrf.exempt  # Exempt from CSRF since it's an API endpoint with auth + rate limiting
    def process_bulk_search(session_id):
        print(f"DEBUG: Starting bulk search for session {session_id}, user {current_user.id}")
        search_session = SearchSession.query.filter_by(
            id=session_id, user_id=current_user.id).first_or_404()
        
        if search_session.status != 'processing':
            return jsonify({'error': 'Search session is not in processing state'}), 400
        
        try:
            # Parse keywords
            keyword_sets = parse_domain_list(search_session.keyword_list)
            
            # Check and deduct coins upfront (skip for admin users)
            total_cost = len(keyword_sets)
            if current_user.role != UserRole.ADMIN and current_user.coins < total_cost:
                search_session.status = 'failed'
                db.session.commit()
                return jsonify({'error': 'Insufficient coins'}), 400
            
            # Deduct all coins at once (skip for admin users)
            if current_user.role != UserRole.ADMIN:
                for _ in range(total_cost):
                    current_user.deduct_coins(1, 'bulk_search')
            
            # Start processing timer
            processing_start = datetime.utcnow()
            all_results = []
            
            # Progress tracking callback
            def update_progress(progress, current_keyword):
                search_session.progress = progress
                search_session.current_keyword = current_keyword
                db.session.commit()
            
            # Use bulk search with adaptive max results
            def adaptive_bulk_search():
                """Try bulk search with reducing max_results: 100, 90, 80, 70, etc."""
                for attempt_results in range(100, 9, -10):  # 100, 90, 80, 70, 60, 50, 40, 30, 20, 10
                    try:
                        print(f"DEBUG: Trying bulk search with max_results={attempt_results}")
                        bulk_results = app.domain_analyzer.api_manager.search_google_bulk(
                            keyword_sets, progress_callback=update_progress, max_results=attempt_results, flask_app=app
                        )
                        print(f"DEBUG: Bulk search successful with max_results={attempt_results}, got {len(bulk_results)} results")
                        return bulk_results, attempt_results
                        
                    except Exception as e:
                        print(f"DEBUG: Bulk search failed with max_results={attempt_results}, error: {str(e)}")
                        if attempt_results <= 10:  # Last attempt
                            raise e  # Re-raise the last error
                        continue  # Try with fewer results
                
                # If we get here, all attempts failed
                raise Exception("All adaptive bulk search attempts failed")
            
            try:
                bulk_results, used_max_results = adaptive_bulk_search()
                print(f"DEBUG: Final bulk search completed with max_results={used_max_results}")
            except Exception as e:
                print(f"DEBUG: All adaptive bulk search attempts failed: {str(e)}")
                bulk_results = []
            print(f"DEBUG: Bulk search completed, got {len(bulk_results)} results")
            
            # Process results with upgrade analysis and save to database in batches
            batch_histories = []
            for keywords, raw_results, api_key_used in bulk_results:
                # IMPORTANT: Analyze raw results for upgrade opportunities with duplicate domain handling
                analyzed_results = []
                parsed_keywords = app.domain_analyzer.parse_keywords(keywords)
                
                # Track domains to handle duplicates at different ranks
                domain_tracker = {}
                
                for result in raw_results:
                    competitor_domain = app.domain_analyzer.extract_domain_from_url(result['url'])
                    
                    if competitor_domain:
                        # Check keyword match for upgrade opportunities
                        match_result = app.domain_analyzer.check_keyword_match(parsed_keywords, competitor_domain)
                        
                        # Include all results with match details
                        if match_result['match_count'] > 0:
                            result_data = {
                                'Keywords': keywords,
                                'Competitor_Domain': competitor_domain,
                                'Search_Keywords': ', '.join(parsed_keywords),
                                'Matched_Keywords': ', '.join(match_result['matches']),
                                'Match_Count': match_result['match_count'],
                                'Total_Keywords': match_result['total_keywords'],
                                'Is_Upgrade': match_result['is_upgrade'],
                                'Google_Rank': result['rank'],
                                'Competitor_Title': result['title']
                            }
                            
                            # Handle duplicate domains - combine ranks
                            if competitor_domain in domain_tracker:
                                # Update existing entry with combined ranks
                                existing_result = domain_tracker[competitor_domain]
                                existing_ranks = str(existing_result['Google_Rank']).split(' and ')
                                new_rank = str(result['rank'])
                                
                                if new_rank not in existing_ranks:
                                    combined_ranks = existing_ranks + [new_rank]
                                    # Sort ranks numerically and format
                                    sorted_ranks = sorted([int(r.replace('#', '')) for r in combined_ranks if r.replace('#', '').isdigit()])
                                    existing_result['Google_Rank'] = ' and '.join([f"#{r}" for r in sorted_ranks])
                                    existing_result['Competitor_Title'] = result['title']  # Keep latest title
                            else:
                                # First occurrence of this domain
                                result_data['Google_Rank'] = f"#{result['rank']}"
                                domain_tracker[competitor_domain] = result_data
                                analyzed_results.append(result_data)
                
                search_history = SearchHistory()
                search_history.user_id = current_user.id
                search_history.keywords = keywords
                search_history.set_results(analyzed_results)  # Save analyzed results with upgrade info
                search_history.api_key_used = api_key_used
                search_history.session_id = session_id
                
                batch_histories.append(search_history)
                all_results.extend(analyzed_results)
                
                # Batch insert every 50 records
                if len(batch_histories) >= 50:
                    db.session.add_all(batch_histories)
                    db.session.commit()
                    batch_histories = []
            
            # Insert remaining records
            if batch_histories:
                db.session.add_all(batch_histories)
            
            # Group results by keyword for upgrade counting (1 keyword = 1 upgrade opportunity)
            def group_results_by_keyword(results):
                """Group competitor domains under same keyword as one upgrade opportunity"""
                grouped = {}
                for result in results:
                    keyword = result['Keywords']
                    if keyword not in grouped:
                        grouped[keyword] = {
                            'Keywords': keyword,
                            'Competitors': [],
                            'Has_Upgrade': False,
                            'Total_Competitors': 0,
                            'Upgrade_Competitors': 0,
                            'upkeyword': False  # Track if this keyword has upgrades for dashboard
                        }
                    
                    # Add competitor to this keyword group
                    grouped[keyword]['Competitors'].append(result)
                    grouped[keyword]['Total_Competitors'] += 1
                    
                    # Track if this keyword group has any upgrade opportunities
                    if result.get('Is_Upgrade', False):
                        grouped[keyword]['Has_Upgrade'] = True
                        grouped[keyword]['upkeyword'] = True  # Mark as having upgrades
                        grouped[keyword]['Upgrade_Competitors'] += 1
                
                return grouped
            
            # Group results and count unique keywords with upgrades
            grouped_results = group_results_by_keyword(all_results)
            upgrade_keyword_count = len([group for group in grouped_results.values() if group['Has_Upgrade']])
            
            # Update session with final results
            processing_end = datetime.utcnow()
            search_session.total_results = len(all_results)
            search_session.upgrade_results = upgrade_keyword_count  # Count unique keywords, not individual domains
            search_session.status = 'completed'
            search_session.progress = 100.0
            search_session.processing_time = (processing_end - processing_start).total_seconds()
            search_session.completed_at = processing_end
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'total_results': search_session.total_results,
                'upgrade_results': search_session.upgrade_results,
                'processing_time': search_session.processing_time,
                'session_url': url_for('view_search_session', session_id=session_id)
            })
            
        except Exception as e:
            search_session.status = 'failed'
            search_session.current_keyword = f'Error: {str(e)}'
            db.session.commit()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/search-progress/<int:session_id>')
    @client_required
    def get_search_progress(session_id):
        search_session = SearchSession.query.filter_by(
            id=session_id, user_id=current_user.id).first_or_404()
        
        return jsonify({
            'progress': search_session.progress,
            'current_keyword': search_session.current_keyword,
            'status': search_session.status,
            'total_results': search_session.total_results,
            'upgrade_results': search_session.upgrade_results
        })
    
    @app.route('/download/<format>')
    @client_required
    def download_results(format, session_id=None):
        # Get results from the most recent search or specific session
        search_id = session.get('latest_session_id')
        if not session_id:
            session_id = request.args.get('session_id')
        
        if session_id:
            # Download from specific search session (for bulk searches)
            search_session = SearchSession.query.filter_by(
                id=session_id, user_id=current_user.id).first()
            if not search_session:
                flash('Search session not found', 'error')
                return redirect(url_for('client_dashboard'))
            
            # Get ALL search history entries for this session
            recent_searches = SearchHistory.query.filter_by(
                session_id=session_id, user_id=current_user.id).all()
        else:
            # Get from latest session
            if not search_id:
                flash('No recent search results to download', 'error')
                return redirect(url_for('search'))
            
            # Get search session
            search_session = SearchSession.query.filter_by(
                id=search_id, user_id=current_user.id).first()
            if not search_session:
                flash('Search session not found', 'error')
                return redirect(url_for('search'))
            
            recent_searches = SearchHistory.query.filter_by(
                session_id=search_session.id, user_id=current_user.id).all()
        
        # Compile ALL results (including non-upgrade opportunities)
        results = []
        for search in recent_searches:
            search_results = search.get_results()
            if search_results:
                # Add the Keywords column (original search keywords)
                for result in search_results:
                    result['Keywords'] = search.keywords
                results.extend(search_results)
        
        if not results:
            flash('No search results to download', 'error')
            return redirect(url_for('search'))
        
        # Create DataFrame with exact column structure as requested
        df = pd.DataFrame(results)
        
        # Ensure exact column order and names as specified: 
        # "Keywords     Competitor_Domain       Search_Keywords Matched_Keywords        Match_Count     Total_Keywords  Is_Upgrade      Google_Rank     Competitor_Title"
        required_columns = [
            'Keywords', 'Competitor_Domain', 'Search_Keywords', 
            'Matched_Keywords', 'Match_Count', 'Total_Keywords', 
            'Is_Upgrade', 'Google_Rank', 'Competitor_Title'
        ]
        
        # Select only existing columns in the correct order
        existing_columns = [col for col in required_columns if col in df.columns]
        df = df[existing_columns]
        
        if format == 'csv':
            csv_buffer = io.StringIO()
            # Use tab separator to match the original format shown by user
            df.to_csv(csv_buffer, index=False, sep='\t')
            csv_data = csv_buffer.getvalue()
            
            return Response(
                csv_data,
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=keyword_upgrade_opportunities.csv'}
            )
        
        elif format == 'excel':
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='All Results', index=False)
            excel_data = excel_buffer.getvalue()
            
            return Response(
                excel_data,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                headers={'Content-Disposition': 'attachment; filename=keyword_upgrade_opportunities.xlsx'}
            )
    
    
    @app.route('/history')
    @client_required
    def search_history():
        page = request.args.get('page', 1, type=int)
        searches = SearchHistory.query.filter_by(user_id=current_user.id).order_by(
            SearchHistory.created_at.desc()).paginate(
            page=page, per_page=10, error_out=False)
        
        return render_template('client/history.html', searches=searches)
    
    @app.route('/coins')
    @client_required
    def coins_dashboard():
        # Get recent transactions for this user
        recent_transactions = CoinTransaction.query.filter_by(
            user_id=current_user.id
        ).order_by(CoinTransaction.created_at.desc()).limit(20).all()
        
        # Calculate total spent and earned
        total_purchased = db.session.query(db.func.sum(CoinTransaction.amount)).filter_by(
            user_id=current_user.id
        ).filter(CoinTransaction.amount > 0).scalar() or 0
        
        total_spent = abs(db.session.query(db.func.sum(CoinTransaction.amount)).filter_by(
            user_id=current_user.id
        ).filter(CoinTransaction.amount < 0).scalar() or 0)
        
        return render_template('client/coins.html',
                             current_balance=current_user.coins,
                             total_purchased=total_purchased,
                             total_spent=total_spent,
                             recent_transactions=recent_transactions)
    
    @app.route('/buy-coins')
    @client_required
    def buy_coins():
        packages = PricingPackage.query.filter_by(is_active=True).all()
        payment_methods = PaymentMethod.query.filter_by(is_active=True).all()
        
        # Get primary Stripe method for frontend
        stripe_method = next((pm for pm in payment_methods if pm.method_type == PaymentMethodType.STRIPE), None)
        stripe_public_key = stripe_method.stripe_public_key if stripe_method else None
        
        return render_template('client/buy_coins.html', 
                             packages=packages,
                             payment_methods=payment_methods,
                             stripe_public_key=stripe_public_key)
    
    @app.route('/create-payment-intent', methods=['POST'])
    @client_required
    def create_payment_intent():
        package_id = request.json.get('package_id')
        package = PricingPackage.query.get_or_404(package_id)
        
        # Get active Stripe payment method
        stripe_method = PaymentMethod.query.filter_by(
            method_type=PaymentMethodType.STRIPE,
            is_active=True
        ).first()
        
        if not stripe_method or not stripe_method.stripe_secret_key:
            return jsonify({'error': 'Stripe payment not configured'}), 400
        
        try:
            # Use configured Stripe secret key
            stripe.api_key = stripe_method.stripe_secret_key
            
            # Create payment intent
            intent = stripe.PaymentIntent.create(
                amount=package.price_cents,
                currency='usd',
                metadata={
                    'user_id': current_user.id,
                    'package_id': package_id,
                    'coins': package.coins
                }
            )
            
            return jsonify({
                'client_secret': intent.client_secret
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    @app.route('/payment-success')
    @client_required
    def payment_success():
        payment_intent_id = request.args.get('payment_intent')
        
        if payment_intent_id:
            # Retrieve the payment intent to get metadata
            intent = stripe.PaymentIntent.retrieve(payment_intent_id)
            
            if intent.status == 'succeeded':
                coins = int(intent.metadata.get('coins', 0))
                amount_paid = intent.amount / 100  # Convert from cents to dollars
                
                # Add coins to user account
                current_user.add_coins(coins, 'purchase')
                db.session.commit()
                
                # Send purchase confirmation email
                try:
                    from email_service import email_service
                    email_service.send_credit_purchase_notification(
                        current_user.email,
                        current_user.email.split('@')[0],
                        amount_paid,
                        coins,
                        payment_intent_id
                    )
                except Exception as e:
                    print(f"Failed to send purchase confirmation email: {e}")
                
                flash(f'Payment successful! {coins} coins added to your account.', 'success')
            else:
                flash('Payment was not successful.', 'error')
        
        return redirect(url_for('client_dashboard'))
    
    @app.route('/create-paypal-payment', methods=['POST'])
    @client_required
    def create_paypal_payment():
        package_id = request.json.get('package_id')
        package = PricingPackage.query.get_or_404(package_id)
        
        # Check if PayPal is configured
        if not current_app.config.get('PAYPAL_CLIENT_ID') or not current_app.config.get('PAYPAL_CLIENT_SECRET'):
            return jsonify({'error': 'PayPal not configured'}), 400
        
        try:
            paypal = PayPalAPI()
            payment_result = paypal.create_payment(package, current_user)
            
            return jsonify({
                'success': True,
                'payment_id': payment_result['payment_id'],
                'approval_url': payment_result['approval_url']
            })
            
        except Exception as e:
            logger.error(f"PayPal payment creation failed: {str(e)}")
            return jsonify({'error': 'Failed to create PayPal payment'}), 400
    
    @app.route('/paypal-success')
    @client_required 
    def paypal_success():
        payment_id = request.args.get('paymentId')
        payer_id = request.args.get('PayerID')
        
        if not payment_id or not payer_id:
            flash('Invalid PayPal callback parameters', 'error')
            return redirect(url_for('buy_coins'))
        
        try:
            paypal = PayPalAPI()
            result = paypal.execute_payment(payment_id, payer_id)
            
            if result['success']:
                # Add coins to user account
                coins = result['coins']
                current_user.add_coins(coins, 'paypal_purchase')
                db.session.commit()
                
                # Log the transaction
                logger.info(f"PayPal payment successful: User {current_user.id} purchased {coins} coins")
                
                flash(f'PayPal payment successful! {coins} coins added to your account.', 'success')
            else:
                flash(f'PayPal payment failed: {result.get("message", "Unknown error")}', 'error')
                
        except Exception as e:
            logger.error(f"PayPal payment execution failed: {str(e)}")
            flash('PayPal payment processing failed', 'error')
        
        return redirect(url_for('client_dashboard'))
    
    @app.route('/paypal-cancel')
    @client_required
    def paypal_cancel():
        flash('PayPal payment was cancelled', 'warning')
        return redirect(url_for('buy_coins'))
    
    # Manual Payment Routes
    @app.route('/request-manual-payment', methods=['POST'])
    @client_required
    def request_manual_payment():
        package_id = request.form.get('package_id')
        payment_method = request.form.get('payment_method')
        payment_notes = request.form.get('payment_notes')
        
        package = PricingPackage.query.get_or_404(package_id)
        
        # Create pending transaction
        transaction = CoinTransaction()
        transaction.user_id = current_user.id
        transaction.amount = package.coins
        transaction.transaction_type = 'manual_payment'
        transaction.status = TransactionStatus.PENDING
        transaction.payment_method = payment_method
        transaction.payment_notes = payment_notes
        
        db.session.add(transaction)
        db.session.commit()
        
        flash(f'Payment request submitted! You will receive {package.coins} coins after admin approval.', 'info')
        return redirect(url_for('client_dashboard'))
    
    # Admin Payment Management Routes
    @app.route('/admin/payments')
    @admin_required
    def admin_payments():
        # Get all pending manual payments
        pending_payments = CoinTransaction.query.filter_by(
            transaction_type='manual_payment',
            status=TransactionStatus.PENDING
        ).order_by(CoinTransaction.created_at.desc()).all()
        
        # Get recent processed payments
        processed_payments = CoinTransaction.query.filter_by(
            transaction_type='manual_payment'
        ).filter(
            CoinTransaction.status.in_([TransactionStatus.COMPLETED, TransactionStatus.FAILED])
        ).order_by(CoinTransaction.processed_at.desc()).limit(20).all()
        
        return render_template('admin/payments.html', 
                             pending_payments=pending_payments,
                             processed_payments=processed_payments)
    
    @app.route('/admin/payments/<int:transaction_id>/approve', methods=['POST'])
    @admin_required
    def approve_payment(transaction_id):
        transaction = CoinTransaction.query.get_or_404(transaction_id)
        admin_notes = request.form.get('admin_notes', '')
        
        if transaction.status != TransactionStatus.PENDING:
            flash('Transaction has already been processed.', 'error')
            return redirect(url_for('admin_payments'))
        
        # Approve the payment
        transaction.status = TransactionStatus.COMPLETED
        transaction.processed_by = current_user.id
        transaction.processed_at = datetime.utcnow()
        transaction.admin_notes = admin_notes
        
        # Add coins to user account
        user = User.query.get(transaction.user_id)
        user.coins += transaction.amount
        
        db.session.commit()
        
        flash(f'Payment approved! {transaction.amount} coins added to {user.email}', 'success')
        return redirect(url_for('admin_payments'))
    
    @app.route('/admin/payments/<int:transaction_id>/reject', methods=['POST'])
    @admin_required
    def reject_payment(transaction_id):
        transaction = CoinTransaction.query.get_or_404(transaction_id)
        admin_notes = request.form.get('admin_notes', '')
        
        if transaction.status != TransactionStatus.PENDING:
            flash('Transaction has already been processed.', 'error')
            return redirect(url_for('admin_payments'))
        
        # Reject the payment
        transaction.status = TransactionStatus.FAILED
        transaction.processed_by = current_user.id
        transaction.processed_at = datetime.utcnow()
        transaction.admin_notes = admin_notes
        
        db.session.commit()
        
        user = User.query.get(transaction.user_id)
        flash(f'Payment rejected for {user.email}. Reason: {admin_notes or "No reason provided"}', 'warning')
        return redirect(url_for('admin_payments'))
    
    # SMTP Configuration Routes
    @app.route('/admin/smtp-settings', methods=['GET', 'POST'])
    @admin_required
    def admin_smtp_settings():
        if request.method == 'POST':
            # Get form data
            smtp_server = request.form.get('smtp_server', 'smtp.gmail.com')
            smtp_port = int(request.form.get('smtp_port', 587))
            smtp_username = request.form.get('smtp_username')
            smtp_password = request.form.get('smtp_password')
            sender_email = request.form.get('sender_email')
            sender_name = request.form.get('sender_name', 'Domain Upgrade Pro')
            admin_email = request.form.get('admin_email')
            
            if not all([smtp_username, smtp_password, sender_email, admin_email]):
                flash('All SMTP fields are required.', 'error')
                return render_template('admin/smtp_settings.html')
            
            # Check if settings exist, update or create
            smtp_settings = SMTPSettings.query.first()
            if smtp_settings:
                smtp_settings.smtp_server = smtp_server
                smtp_settings.smtp_port = smtp_port
                smtp_settings.smtp_username = smtp_username
                smtp_settings.smtp_password = smtp_password
                smtp_settings.sender_email = sender_email
                smtp_settings.sender_name = sender_name
                smtp_settings.admin_email = admin_email
                smtp_settings.updated_at = datetime.utcnow()
            else:
                smtp_settings = SMTPSettings(
                    smtp_server=smtp_server,
                    smtp_port=smtp_port,
                    smtp_username=smtp_username,
                    smtp_password=smtp_password,
                    sender_email=sender_email,
                    sender_name=sender_name,
                    admin_email=admin_email
                )
                db.session.add(smtp_settings)
            
            db.session.commit()
            flash('SMTP settings saved successfully!', 'success')
            return redirect(url_for('admin_smtp_settings'))
        
        # GET request - show current settings
        smtp_settings = SMTPSettings.query.first()
        return render_template('admin/smtp_settings.html', smtp_settings=smtp_settings)
    
    @app.route('/admin/system-settings', methods=['GET', 'POST'])
    @admin_required
    def admin_system_settings():
        """Admin page for configuring system-wide settings like URL limits per keyword and blacklisted domains"""
        from models import SystemSettings, BlacklistedDomain
        from domain_utils import extract_main_domain, add_common_blacklist_domains
        
        if request.method == 'POST':
            action = request.form.get('action', 'save_settings')
            
            # Handle blacklist actions
            if action == 'add_blacklist':
                domain_input = request.form.get('domain', '').strip()
                reason = request.form.get('reason', '').strip()
                
                if domain_input:
                    clean_domain = extract_main_domain(domain_input)
                    if clean_domain:
                        existing = BlacklistedDomain.query.filter_by(domain=clean_domain).first()
                        if not existing:
                            blacklisted_domain = BlacklistedDomain(
                                domain=clean_domain,
                                reason=reason or 'Added via system settings',
                                added_by=current_user.id,
                                is_active=True
                            )
                            db.session.add(blacklisted_domain)
                            db.session.commit()
                            flash(f'✅ Domain "{clean_domain}" added to blacklist', 'success')
                        else:
                            flash(f'⚠️ Domain "{clean_domain}" is already blacklisted', 'warning')
                    else:
                        flash('❌ Invalid domain format', 'error')
                return redirect(url_for('admin_system_settings'))
            
            elif action == 'add_common_domains':
                common_domains = add_common_blacklist_domains()
                added_count = 0
                
                for domain in common_domains:
                    existing = BlacklistedDomain.query.filter_by(domain=domain).first()
                    if not existing:
                        blacklisted_domain = BlacklistedDomain(
                            domain=domain,
                            reason="Common social media/marketplace domain",
                            added_by=current_user.id,
                            is_active=True
                        )
                        db.session.add(blacklisted_domain)
                        added_count += 1
                
                db.session.commit()
                flash(f'✅ Added {added_count} common domains to blacklist', 'success')
                return redirect(url_for('admin_system_settings'))
            
            elif action == 'bulk_add_blacklist':
                domains_text = request.form.get('domains_list', '').strip()
                reason = request.form.get('bulk_reason', 'Bulk import via system settings')
                
                if domains_text:
                    domain_lines = [line.strip() for line in domains_text.split('\n') if line.strip()]
                    added_count = 0
                    
                    for domain_line in domain_lines:
                        clean_domain = extract_main_domain(domain_line)
                        if clean_domain:
                            existing = BlacklistedDomain.query.filter_by(domain=clean_domain).first()
                            if not existing:
                                blacklisted_domain = BlacklistedDomain(
                                    domain=clean_domain,
                                    reason=reason,
                                    added_by=current_user.id,
                                    is_active=True
                                )
                                db.session.add(blacklisted_domain)
                                added_count += 1
                    
                    db.session.commit()
                    flash(f'✅ Added {added_count} domains to blacklist', 'success')
                return redirect(url_for('admin_system_settings'))
            
            elif action == 'toggle_blacklist':
                domain_id = request.form.get('domain_id')
                if domain_id:
                    domain = BlacklistedDomain.query.get(domain_id)
                    if domain:
                        domain.is_active = not domain.is_active
                        db.session.commit()
                        status = "activated" if domain.is_active else "deactivated"
                        flash(f'✅ Domain "{domain.domain}" has been {status}', 'success')
                return redirect(url_for('admin_system_settings'))
            
            elif action == 'delete_blacklist':
                domain_id = request.form.get('domain_id')
                if domain_id:
                    domain = BlacklistedDomain.query.get(domain_id)
                    if domain:
                        domain_name = domain.domain
                        db.session.delete(domain)
                        db.session.commit()
                        flash(f'✅ Domain "{domain_name}" removed from blacklist', 'success')
                return redirect(url_for('admin_system_settings'))
            
            else:
                # Handle system settings save
                max_urls_per_keyword = int(request.form.get('max_urls_per_keyword', 2000))
                description = request.form.get('description', 'Maximum number of URLs to scrape per keyword from Google search')
                is_active = 'is_active' in request.form
                
                # Validate URL limit
                if max_urls_per_keyword < 10 or max_urls_per_keyword > 10000:
                    flash('URL limit must be between 10 and 10,000', 'error')
                    return redirect(url_for('admin_system_settings'))
                
                # Check if settings exist, update or create
                settings = SystemSettings.query.first()
                if settings:
                    settings.max_urls_per_keyword = max_urls_per_keyword
                    settings.description = description
                    settings.is_active = is_active
                    settings.updated_at = datetime.utcnow()
                else:
                    settings = SystemSettings(
                        max_urls_per_keyword=max_urls_per_keyword,
                        description=description,
                        is_active=is_active
                    )
                    db.session.add(settings)
                
                db.session.commit()
                flash(f'✅ System settings saved! URL limit set to {max_urls_per_keyword} per keyword.', 'success')
                return redirect(url_for('admin_system_settings'))
        
        # GET request - show current settings and blacklisted domains
        settings = SystemSettings.query.first()
        blacklisted_domains = BlacklistedDomain.query.order_by(BlacklistedDomain.created_at.desc()).all()
        
        return render_template('admin/system_settings.html', 
                             settings=settings, 
                             blacklisted_domains=blacklisted_domains)
    
    # Contact Form Routes
    @app.route('/contact', methods=['GET', 'POST'])
    def contact():
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            subject = request.form.get('subject')
            message = request.form.get('message')
            
            if not all([name, email, subject, message]):
                flash('All fields are required.', 'error')
                return render_template('contact.html')
            
            # Save contact form
            contact_form = ContactForm(
                name=name,
                email=email,
                subject=subject,
                message=message,
                ip_address=request.remote_addr
            )
            db.session.add(contact_form)
            db.session.commit()
            
            # Send email notification to admin
            try:
                send_contact_notification(contact_form)
                flash('Thank you for your message! We will get back to you soon.', 'success')
            except Exception as e:
                flash('Message saved but email notification failed. Admin will still see your message.', 'warning')
                print(f"Email notification error: {e}")
            
            return redirect(url_for('contact'))
        
        return render_template('contact.html')
    
    @app.route('/admin/contact-forms')
    @admin_required
    def admin_contact_forms():
        page = request.args.get('page', 1, type=int)
        contact_forms = ContactForm.query.order_by(ContactForm.created_at.desc()).paginate(
            page=page, per_page=20, error_out=False
        )
        return render_template('admin/contact_forms.html', contact_forms=contact_forms)
    
    @app.route('/admin/contact-forms/<int:form_id>/mark-read', methods=['POST'])
    @admin_required
    def mark_contact_read(form_id):
        contact_form = ContactForm.query.get_or_404(form_id)
        contact_form.is_read = True
        db.session.commit()
        flash('Message marked as read.', 'success')
        return redirect(url_for('admin_contact_forms'))
    
    def send_contact_notification(contact_form):
        """Send email notification to admin when contact form is submitted"""
        smtp_settings = SMTPSettings.query.filter_by(is_active=True).first()
        if not smtp_settings:
            return False
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = smtp_settings.sender_email
            msg['To'] = smtp_settings.admin_email
            msg['Subject'] = f"New Contact Form: {contact_form.subject}"
            
            # Email body
            body = f"""
New contact form submission from Domain Upgrade Pro:

Name: {contact_form.name}
Email: {contact_form.email}
Subject: {contact_form.subject}
IP Address: {contact_form.ip_address}
Date: {contact_form.created_at.strftime('%Y-%m-%d %H:%M:%S')}

Message:
{contact_form.message}

---
This is an automated message from Domain Upgrade Pro.
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(smtp_settings.smtp_server, smtp_settings.smtp_port)
            server.starttls()
            server.login(smtp_settings.smtp_username, smtp_settings.smtp_password)
            text = msg.as_string()
            server.sendmail(smtp_settings.sender_email, smtp_settings.admin_email, text)
            server.quit()
            
            return True
        except Exception as e:
            print(f"Email sending error: {e}")
            return False
    
    # Search Session Management Routes
    @app.route('/search-session/<int:session_id>')
    @client_required
    def view_search_session(session_id):
        search_session = SearchSession.query.filter_by(
            id=session_id, user_id=current_user.id).first_or_404()
        
        # Get all searches in this session
        searches = SearchHistory.query.filter_by(session_id=session_id).all()
        
        # Collect all results
        all_results = []
        for search in searches:
            results = search.get_results()
            if results:
                all_results.extend(results)
        
        # Group results by keyword for display (same logic as search page)
        def group_results_by_keyword(results):
            """Group competitor domains under same keyword as one upgrade opportunity"""
            grouped = {}
            for result in results:
                keyword = result['Keywords']
                if keyword not in grouped:
                    grouped[keyword] = {
                        'Keywords': keyword,
                        'Competitors': [],
                        'Has_Upgrade': False,
                        'Total_Competitors': 0,
                        'Upgrade_Competitors': 0,
                        'upkeyword': False  # Track if this keyword has upgrades for dashboard
                    }
                
                # Add competitor to this keyword group
                grouped[keyword]['Competitors'].append(result)
                grouped[keyword]['Total_Competitors'] += 1
                
                # Track if this keyword group has any upgrade opportunities
                if result.get('Is_Upgrade', False):
                    grouped[keyword]['Has_Upgrade'] = True
                    grouped[keyword]['upkeyword'] = True  # Mark as having upgrades
                    grouped[keyword]['Upgrade_Competitors'] += 1
            
            return grouped
        
        # Group results and filter for upgrade opportunities
        grouped_results = group_results_by_keyword(all_results) if all_results else {}
        upgrade_groups = {k: v for k, v in grouped_results.items() if v['Has_Upgrade']}
        
        return render_template('client/search_session.html',
                             session=search_session,
                             searches=searches,
                             all_results=all_results,
                             grouped_results=upgrade_groups,
                             upgrade_count=len(upgrade_groups))
    
    @app.route('/delete-search-session/<int:session_id>', methods=['POST'])
    @client_required
    def delete_search_session(session_id):
        search_session = SearchSession.query.filter_by(
            id=session_id, user_id=current_user.id).first_or_404()
        
        # Delete associated search history
        SearchHistory.query.filter_by(session_id=session_id).delete()
        
        # Delete the session
        db.session.delete(search_session)
        db.session.commit()
        
        flash('Search session deleted successfully', 'success')
        return redirect(url_for('search_history'))
    
    @app.route('/download-session/<int:session_id>/<format>')
    @client_required
    def download_session_results(session_id, format):
        search_session = SearchSession.query.filter_by(
            id=session_id, user_id=current_user.id).first_or_404()
        
        # Get ALL results from this session (including non-upgrade opportunities)
        searches = SearchHistory.query.filter_by(session_id=session_id).all()
        results = []
        for search in searches:
            search_results = search.get_results()
            if search_results:
                # Add the Keywords column (original search keywords)  
                for result in search_results:
                    result['Keywords'] = search.keywords
                results.extend(search_results)
        
        if not results:
            flash('No results to download for this search session', 'error')
            return redirect(url_for('view_search_session', session_id=session_id))
        
        # Create DataFrame with exact column structure as requested
        df = pd.DataFrame(results)
        
        # Ensure exact column order and names as specified:
        # "Keywords     Competitor_Domain       Search_Keywords Matched_Keywords        Match_Count     Total_Keywords  Is_Upgrade      Google_Rank     Competitor_Title"
        required_columns = [
            'Keywords', 'Competitor_Domain', 'Search_Keywords', 
            'Matched_Keywords', 'Match_Count', 'Total_Keywords', 
            'Is_Upgrade', 'Google_Rank', 'Competitor_Title'
        ]
        
        # Select only existing columns in the correct order
        existing_columns = [col for col in required_columns if col in df.columns]
        df = df[existing_columns]
        
        timestamp = search_session.created_at.strftime('%Y%m%d_%H%M%S')
        
        if format == 'csv':
            csv_buffer = io.StringIO()
            # Use tab separator to match the original format shown by user
            df.to_csv(csv_buffer, index=False, sep='\t')
            csv_data = csv_buffer.getvalue()
            
            return Response(
                csv_data,
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=search_session_{session_id}_{timestamp}.csv'}
            )
        
        elif format == 'excel':
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='All Results', index=False)
            excel_data = excel_buffer.getvalue()
            
            return Response(
                excel_data,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                headers={'Content-Disposition': f'attachment; filename=search_session_{session_id}_{timestamp}.xlsx'}
            )
    
    # Payment Method Management Routes
    @app.route('/admin/payment-methods')
    @admin_required
    def admin_payment_methods():
        payment_methods = PaymentMethod.query.order_by(PaymentMethod.created_at.desc()).all()
        return render_template('admin/payment_methods.html', payment_methods=payment_methods)
    
    @app.route('/admin/payment-methods/add', methods=['GET', 'POST'])
    @admin_required
    def add_payment_method():
        if request.method == 'POST':
            method_type = request.form.get('method_type')
            name = request.form.get('name')
            
            payment_method = PaymentMethod()
            payment_method.method_type = PaymentMethodType(method_type)
            payment_method.name = name
            
            if method_type == 'STRIPE':
                payment_method.stripe_public_key = request.form.get('stripe_public_key')
                payment_method.stripe_secret_key = request.form.get('stripe_secret_key')
                payment_method.stripe_webhook_secret = request.form.get('stripe_webhook_secret')
            elif method_type == 'PAYPAL':
                payment_method.paypal_email = request.form.get('paypal_email')
                payment_method.paypal_instructions = request.form.get('paypal_instructions')
            
            db.session.add(payment_method)
            db.session.commit()
            
            flash(f'{name} payment method added successfully', 'success')
            return redirect(url_for('admin_payment_methods'))
        
        return render_template('admin/add_payment_method.html')
    
    @app.route('/admin/payment-methods/<int:method_id>/edit', methods=['GET', 'POST'])
    @admin_required
    def edit_payment_method(method_id):
        payment_method = PaymentMethod.query.get_or_404(method_id)
        
        if request.method == 'POST':
            payment_method.name = request.form.get('name')
            
            if payment_method.method_type == PaymentMethodType.STRIPE:
                payment_method.stripe_public_key = request.form.get('stripe_public_key')
                payment_method.stripe_secret_key = request.form.get('stripe_secret_key')
                payment_method.stripe_webhook_secret = request.form.get('stripe_webhook_secret')
            elif payment_method.method_type == PaymentMethodType.PAYPAL:
                payment_method.paypal_email = request.form.get('paypal_email')
                payment_method.paypal_instructions = request.form.get('paypal_instructions')
            
            payment_method.updated_at = datetime.utcnow()
            db.session.commit()
            
            flash(f'{payment_method.name} updated successfully', 'success')
            return redirect(url_for('admin_payment_methods'))
        
        return render_template('admin/edit_payment_method.html', payment_method=payment_method)
    
    @app.route('/admin/payment-methods/<int:method_id>/toggle', methods=['POST'])
    @admin_required
    def toggle_payment_method(method_id):
        payment_method = PaymentMethod.query.get_or_404(method_id)
        payment_method.is_active = not payment_method.is_active
        payment_method.updated_at = datetime.utcnow()
        db.session.commit()
        
        status = "activated" if payment_method.is_active else "deactivated"
        flash(f'{payment_method.name} {status} successfully', 'success')
        return redirect(url_for('admin_payment_methods'))
    
    # Domain Blacklist Management Routes
    @app.route('/admin/blacklisted-domains')
    @admin_required
    def admin_blacklisted_domains():
        """Admin page for managing blacklisted domains"""
        from models import BlacklistedDomain
        
        page = request.args.get('page', 1, type=int)
        blacklisted_domains = BlacklistedDomain.query.order_by(BlacklistedDomain.created_at.desc()).paginate(
            page=page, per_page=20, error_out=False
        )
        
        # Get statistics
        total_domains = BlacklistedDomain.query.count()
        active_domains = BlacklistedDomain.query.filter_by(is_active=True).count()
        
        return render_template('admin/blacklisted_domains.html', 
                             blacklisted_domains=blacklisted_domains,
                             total_domains=total_domains,
                             active_domains=active_domains)
    
    @app.route('/admin/blacklisted-domains/add', methods=['POST'])
    @admin_required
    def add_blacklisted_domain():
        """Add a new domain to the blacklist"""
        from models import BlacklistedDomain
        from domain_utils import extract_main_domain
        
        domain_input = request.form.get('domain', '').strip()
        reason = request.form.get('reason', '').strip()
        
        if not domain_input:
            flash('Domain is required', 'error')
            return redirect(url_for('admin_blacklisted_domains'))
        
        # Extract and clean the domain
        clean_domain = extract_main_domain(domain_input)
        if not clean_domain:
            flash('Invalid domain format', 'error')
            return redirect(url_for('admin_blacklisted_domains'))
        
        # Check if domain already exists
        existing = BlacklistedDomain.query.filter_by(domain=clean_domain).first()
        if existing:
            flash(f'Domain "{clean_domain}" is already blacklisted', 'warning')
            return redirect(url_for('admin_blacklisted_domains'))
        
        # Add the domain
        blacklisted_domain = BlacklistedDomain(
            domain=clean_domain,
            reason=reason or 'Manually added by admin',
            added_by=current_user.id,
            is_active=True
        )
        
        db.session.add(blacklisted_domain)
        db.session.commit()
        
        flash(f'Domain "{clean_domain}" added to blacklist', 'success')
        return redirect(url_for('admin_blacklisted_domains'))
    
    @app.route('/admin/blacklisted-domains/bulk-add', methods=['POST'])
    @admin_required
    def bulk_add_blacklisted_domains():
        """Add multiple domains to the blacklist"""
        from models import BlacklistedDomain
        from domain_utils import extract_main_domain, add_common_blacklist_domains
        
        action = request.form.get('action')
        
        if action == 'common_domains':
            # Add common social media and marketplace domains
            common_domains = add_common_blacklist_domains()
            added_count = 0
            
            for domain in common_domains:
                existing = BlacklistedDomain.query.filter_by(domain=domain).first()
                if not existing:
                    blacklisted_domain = BlacklistedDomain(
                        domain=domain,
                        reason="Common social media/marketplace domain - not business focused",
                        added_by=current_user.id,
                        is_active=True
                    )
                    db.session.add(blacklisted_domain)
                    added_count += 1
            
            db.session.commit()
            flash(f'Added {added_count} common domains to blacklist', 'success')
            
        elif action == 'bulk_list':
            # Add domains from textarea
            domains_text = request.form.get('domains_list', '').strip()
            reason = request.form.get('bulk_reason', 'Bulk import by admin')
            
            if not domains_text:
                flash('Please provide a list of domains', 'error')
                return redirect(url_for('admin_blacklisted_domains'))
            
            # Parse domains (one per line)
            domain_lines = [line.strip() for line in domains_text.split('\n') if line.strip()]
            added_count = 0
            skipped_count = 0
            
            for domain_line in domain_lines:
                clean_domain = extract_main_domain(domain_line)
                if clean_domain:
                    existing = BlacklistedDomain.query.filter_by(domain=clean_domain).first()
                    if not existing:
                        blacklisted_domain = BlacklistedDomain(
                            domain=clean_domain,
                            reason=reason,
                            added_by=current_user.id,
                            is_active=True
                        )
                        db.session.add(blacklisted_domain)
                        added_count += 1
                    else:
                        skipped_count += 1
            
            db.session.commit()
            flash(f'Added {added_count} domains to blacklist. Skipped {skipped_count} duplicates.', 'success')
        
        return redirect(url_for('admin_blacklisted_domains'))
    
    @app.route('/admin/blacklisted-domains/<int:domain_id>/toggle', methods=['POST'])
    @admin_required
    def toggle_blacklisted_domain(domain_id):
        """Toggle active status of a blacklisted domain"""
        from models import BlacklistedDomain
        
        domain = BlacklistedDomain.query.get_or_404(domain_id)
        domain.is_active = not domain.is_active
        db.session.commit()
        
        status = "activated" if domain.is_active else "deactivated"
        flash(f'Domain "{domain.domain}" has been {status}', 'success')
        return redirect(url_for('admin_blacklisted_domains'))
    
    @app.route('/admin/blacklisted-domains/<int:domain_id>/delete', methods=['POST'])
    @admin_required
    def delete_blacklisted_domain(domain_id):
        """Permanently delete a blacklisted domain"""
        from models import BlacklistedDomain
        
        domain = BlacklistedDomain.query.get_or_404(domain_id)
        domain_name = domain.domain
        
        db.session.delete(domain)
        db.session.commit()
        
        flash(f'Domain "{domain_name}" has been permanently removed from blacklist', 'success')
        return redirect(url_for('admin_blacklisted_domains'))
    
    @app.route('/admin/blacklisted-domains/<int:domain_id>/edit', methods=['POST'])
    @admin_required
    def edit_blacklisted_domain(domain_id):
        """Edit the reason for a blacklisted domain"""
        from models import BlacklistedDomain
        
        domain = BlacklistedDomain.query.get_or_404(domain_id)
        new_reason = request.form.get('reason', '').strip()
        
        if new_reason:
            domain.reason = new_reason
            db.session.commit()
            flash(f'Updated reason for "{domain.domain}"', 'success')
        else:
            flash('Reason cannot be empty', 'error')
        
        return redirect(url_for('admin_blacklisted_domains'))

    # Installation Setup Wizard
    def is_installed():
        """Check if the application is already installed"""
        return os.path.exists('installed.lock')
    
    def generate_secret_key():
        """Generate a secure secret key"""
        import secrets
        return secrets.token_hex(32)
    
    def write_env_file(config_data):
        """Write configuration to .env file"""
        env_content = f"""# Domain Upgrade Pro SaaS Configuration
# Generated automatically by installation wizard

# Flask Configuration
SECRET_KEY={config_data['secret_key']}
FLASK_ENV=production

# Database Configuration
DATABASE_URL={config_data['database_url']}

# API Keys
SERPER_API_KEY={config_data['serper_api_key']}

# Payment Processing (Optional)
STRIPE_PUBLIC_KEY={config_data.get('stripe_public_key', '')}
STRIPE_SECRET_KEY={config_data.get('stripe_secret_key', '')}
STRIPE_WEBHOOK_SECRET={config_data.get('stripe_webhook_secret', '')}

PAYPAL_CLIENT_ID={config_data.get('paypal_client_id', '')}
PAYPAL_CLIENT_SECRET={config_data.get('paypal_client_secret', '')}
PAYPAL_MODE={config_data.get('paypal_mode', 'sandbox')}

# Email Configuration (Optional)
MAIL_SERVER={config_data.get('mail_server', '')}
MAIL_PORT={config_data.get('mail_port', '587')}
MAIL_USE_TLS={config_data.get('mail_use_tls', 'True')}
MAIL_USERNAME={config_data.get('mail_username', '')}
MAIL_PASSWORD={config_data.get('mail_password', '')}
"""
        
        with open('.env', 'w') as f:
            f.write(env_content)
    
    def create_admin_user(email, password):
        """Create the first admin user"""
        # Check if admin already exists
        existing_admin = User.query.filter_by(role=UserRole.ADMIN).first()
        if existing_admin:
            return False, "Admin user already exists"
        
        try:
            admin_user = User()
            admin_user.email = email
            admin_user.password_hash = hash_password(password)
            admin_user.role = UserRole.ADMIN
            admin_user.coins = 1000  # Give admin some coins
            admin_user.trial_coins_used = True  # Admin doesn't need trial coins
            
            db.session.add(admin_user)
            db.session.commit()
            
            return True, "Admin user created successfully"
        except Exception as e:
            db.session.rollback()
            return False, f"Error creating admin user: {str(e)}"
    
    def create_lock_file():
        """Create installation lock file"""
        with open('installed.lock', 'w') as f:
            f.write(f"Installation completed on {datetime.utcnow().isoformat()}\n")
    
    @app.route('/install', methods=['GET', 'POST'])
    def install():
        # Check if already installed
        if is_installed():
            flash('Application is already installed. Please login to continue.', 'info')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            try:
                # Get form data
                admin_email = request.form.get('admin_email', '').strip()
                admin_password = request.form.get('admin_password', '').strip()
                
                # Database settings
                db_host = request.form.get('db_host', 'localhost').strip()
                db_port = request.form.get('db_port', '5432').strip()
                db_user = request.form.get('db_user', '').strip()
                db_password = request.form.get('db_password', '').strip()
                db_name = request.form.get('db_name', 'domain_upgrade_pro').strip()
                use_sqlite = request.form.get('use_sqlite') == 'on'
                
                # API Keys
                serper_api_key = request.form.get('serper_api_key', '').strip()
                
                # Optional API Keys
                stripe_public_key = request.form.get('stripe_public_key', '').strip()
                stripe_secret_key = request.form.get('stripe_secret_key', '').strip()
                stripe_webhook_secret = request.form.get('stripe_webhook_secret', '').strip()
                
                paypal_client_id = request.form.get('paypal_client_id', '').strip()
                paypal_client_secret = request.form.get('paypal_client_secret', '').strip()
                paypal_mode = request.form.get('paypal_mode', 'sandbox').strip()
                
                # Email settings
                mail_server = request.form.get('mail_server', '').strip()
                mail_port = request.form.get('mail_port', '587').strip()
                mail_username = request.form.get('mail_username', '').strip()
                mail_password = request.form.get('mail_password', '').strip()
                
                # App settings
                secret_key = request.form.get('secret_key', '').strip()
                if not secret_key:
                    secret_key = generate_secret_key()
                
                # Validation
                errors = []
                
                if not admin_email or '@' not in admin_email:
                    errors.append('Valid admin email is required')
                
                if not admin_password or len(admin_password) < 6:
                    errors.append('Admin password must be at least 6 characters')
                
                if not serper_api_key:
                    errors.append('Serper API key is required for core functionality')
                
                if use_sqlite:
                    database_url = 'sqlite:///app.db'
                else:
                    if not all([db_user, db_password, db_name]):
                        errors.append('Database user, password, and name are required for PostgreSQL')
                    else:
                        database_url = f'postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
                
                if errors:
                    for error in errors:
                        flash(error, 'error')
                    return render_template('install.html')
                
                # Prepare configuration data
                config_data = {
                    'secret_key': secret_key,
                    'database_url': database_url,
                    'serper_api_key': serper_api_key,
                    'stripe_public_key': stripe_public_key,
                    'stripe_secret_key': stripe_secret_key,
                    'stripe_webhook_secret': stripe_webhook_secret,
                    'paypal_client_id': paypal_client_id,
                    'paypal_client_secret': paypal_client_secret,
                    'paypal_mode': paypal_mode,
                    'mail_server': mail_server,
                    'mail_port': mail_port,
                    'mail_use_tls': 'True',
                    'mail_username': mail_username,
                    'mail_password': mail_password
                }
                
                # Write .env file
                write_env_file(config_data)
                
                # Initialize database
                try:
                    db.create_all()
                    
                    # Create default pricing packages if they don't exist
                    if not PricingPackage.query.first():
                        packages = [
                            PricingPackage(name='Starter Pack', coins=100, price_cents=1000),  # $10
                            PricingPackage(name='Professional Pack', coins=500, price_cents=4000),  # $40
                            PricingPackage(name='Enterprise Pack', coins=1000, price_cents=7500),  # $75
                        ]
                        for package in packages:
                            db.session.add(package)
                        db.session.commit()
                    
                except Exception as e:
                    flash(f'Database initialization failed: {str(e)}', 'error')
                    # Clean up .env file on failure
                    if os.path.exists('.env'):
                        os.remove('.env')
                    return render_template('install.html')
                
                # Create admin user
                success, message = create_admin_user(admin_email, admin_password)
                if not success:
                    flash(f'Admin user creation failed: {message}', 'error')
                    # Clean up on failure
                    if os.path.exists('.env'):
                        os.remove('.env')
                    return render_template('install.html')
                
                # Create lock file
                create_lock_file()
                
                # Success message
                flash('🎉 Installation completed successfully! You can now login with your admin credentials.', 'success')
                flash('⚠️ Please restart the application to load the new configuration.', 'warning')
                
                # Auto-login the admin user
                try:
                    admin_user = User.query.filter_by(email=admin_email).first()
                    if admin_user:
                        login_user(admin_user)
                        return redirect(url_for('admin_dashboard'))
                except Exception as e:
                    # If auto-login fails, just redirect to login
                    pass
                
                return redirect(url_for('login'))
                
            except Exception as e:
                flash(f'Installation failed: {str(e)}', 'error')
                # Clean up on failure
                if os.path.exists('.env'):
                    os.remove('.env')
                if os.path.exists('installed.lock'):
                    os.remove('installed.lock')
                return render_template('install.html')
        
        # GET request - show installation form
        return render_template('install.html')

    # ==================== BUSINESS SEARCH ROUTES ====================
    
    @app.route('/business-search', methods=['GET', 'POST'])
    @client_required
    @limiter.limit("30 per hour")  # Rate limit for business searches
    @secure_headers
    def business_search():
        from business_search_service import business_search_service
        from models import BusinessSearchSession
        
        if request.method == 'POST':
            # Get and validate input
            keywords = sanitize_input(request.form.get('keywords', ''))
            cities_input = sanitize_input(request.form.get('cities', ''))
            max_results = int(request.form.get('max_results', 20))
            
            # Validate inputs
            validation_rules = {
                'keywords': {'required': True, 'type': 'safe_string', 'max_length': 500},
                'cities': {'required': True, 'type': 'safe_string'}
            }
            
            is_valid, errors = validate_form_data({
                'keywords': keywords,
                'cities': cities_input
            }, validation_rules)
            
            if not is_valid:
                for error in errors:
                    flash(error, 'error')
                return render_template('client/business_search.html')
            
            # Parse cities (one per line)
            cities = [city.strip() for city in cities_input.split('\n') if city.strip()]
            
            if not cities:
                flash('Please enter at least one city', 'error')
                return render_template('client/business_search.html')
            
            # Check if user has enough coins
            total_cost = len(cities)  # 1 coin per city
            if current_user.role != UserRole.ADMIN and current_user.coins < total_cost:
                flash(f'You need {total_cost} coins for this search but only have {current_user.coins} coins.', 'error')
                return redirect(url_for('buy_coins'))
            
            # Deduct coins (skip for admin users)
            if current_user.role != UserRole.ADMIN:
                if not current_user.deduct_coins(total_cost, 'business_search'):
                    flash('Insufficient coins for this search', 'error')
                    return redirect(url_for('buy_coins'))
                db.session.commit()
            
            # Start business search
            try:
                session_id = business_search_service.start_business_search(
                    user_id=current_user.id,
                    keywords=keywords,
                    cities=cities,
                    max_results_per_city=max_results
                )
                
                flash(f'Business search started! Processing {len(cities)} cities...', 'success')
                return redirect(url_for('business_search_processor', session_id=session_id))
                
            except Exception as e:
                logger.error(f"Error starting business search: {str(e)}")
                flash('Error starting business search. Please try again.', 'error')
                return render_template('client/business_search.html')
        
        # GET request - show search form with recent searches
        recent_searches = BusinessSearchSession.query.filter_by(
            user_id=current_user.id
        ).order_by(BusinessSearchSession.created_at.desc()).limit(10).all()
        
        return render_template('client/business_search.html', recent_searches=recent_searches)
    
    @app.route('/business-search-processor/<int:session_id>')
    @client_required
    @secure_headers
    def business_search_processor(session_id):
        from models import BusinessSearchSession
        
        # Verify user owns this session
        session = BusinessSearchSession.query.filter_by(
            id=session_id, user_id=current_user.id
        ).first_or_404()
        
        return render_template('client/business_search_processor.html', session=session)
    
    @app.route('/api/business-search-status/<int:session_id>')
    @client_required
    @csrf.exempt  # API endpoint
    def business_search_status(session_id):
        from business_search_service import business_search_service
        from models import BusinessSearchSession, BusinessData
        
        # Verify user owns this session
        session = BusinessSearchSession.query.filter_by(
            id=session_id, user_id=current_user.id
        ).first()
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        # Check if this is a bulk search with child sessions
        child_sessions = BusinessSearchSession.query.filter_by(parent_session_id=session_id).all()
        
        if child_sessions:
            # Bulk search - return detailed keyword progress
            keyword_progress = []
            total_keywords = len(child_sessions)
            completed_keywords = 0
            current_keyword = None
            overall_progress = 0
            total_businesses = 0
            
            for child_session in child_sessions:
                business_count = BusinessData.query.filter_by(session_id=child_session.id).count()
                total_businesses += business_count
                
                if child_session.status == 'completed':
                    completed_keywords += 1
                    status_icon = '✅'
                    status_text = 'Completed'
                    progress = 100
                elif child_session.status == 'processing':
                    current_keyword = child_session.keywords
                    status_icon = '🔄'
                    status_text = f'Processing ({business_count} URLs found)'
                    progress = child_session.progress or 0
                else:
                    status_icon = '⏳'
                    status_text = 'Pending'
                    progress = 0
                
                keyword_progress.append({
                    'keyword': child_session.keywords,
                    'status': child_session.status,
                    'status_icon': status_icon,
                    'status_text': status_text,
                    'progress': progress,
                    'business_count': business_count,
                    'processing_time': child_session.processing_time or 0
                })
            
            # Calculate overall progress
            overall_progress = (completed_keywords / total_keywords * 100) if total_keywords > 0 else 0
            if current_keyword:
                # Add partial progress for current keyword
                current_session = next((s for s in child_sessions if s.keywords == current_keyword), None)
                if current_session and current_session.progress:
                    overall_progress += (current_session.progress / total_keywords)
            
            return jsonify({
                'status': session.status,
                'is_bulk_search': True,
                'total_keywords': total_keywords,
                'completed_keywords': completed_keywords,
                'current_keyword': current_keyword,
                'progress': min(100, overall_progress),
                'keyword_progress': keyword_progress,
                'total_businesses': total_businesses,
                'processing_time': session.processing_time or 0
            })
        
        else:
            # Single search - get status from service
            status = business_search_service.get_session_status(session_id)
            status['is_bulk_search'] = False
            return jsonify(status)
    
    @app.route('/business-search-results/<int:session_id>')
    @client_required
    @secure_headers
    def business_search_results(session_id):
        from business_search_service import business_search_service
        
        # Get results from service
        results = business_search_service.get_session_results(session_id, current_user.id)
        
        if 'error' in results:
            flash(results['error'], 'error')
            return redirect(url_for('business_search'))
        
        return render_template('client/business_search_results.html', results=results)
    
    @app.route('/download-business-csv/<int:session_id>')
    @client_required
    def download_business_csv(session_id):
        from business_search_service import business_search_service
        from models import BusinessData
        import csv
        import io
        
        # Get session results
        results = business_search_service.get_session_results(session_id, current_user.id)
        
        if 'error' in results:
            flash(results['error'], 'error')
            return redirect(url_for('business_search'))
        
        # Handle bulk search vs single search
        if results.get('is_bulk_search'):
            # Bulk search - combine all keyword results
            businesses = []
            for keyword_result in results['keyword_results']:
                businesses.extend(keyword_result['businesses'])
            
            # Clean keywords for filename
            clean_keywords = 'bulk_search'
            filename = f"bulk_search_all_keywords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        else:
            # Single search - original behavior
            city_filter = request.args.get('city')
            
            # Clean keywords for filename (remove newlines and special characters)
            clean_keywords = results['session']['keywords'].replace('\n', '_').replace('\r', '').replace(' ', '_')
            clean_keywords = ''.join(c for c in clean_keywords if c.isalnum() or c in '_-')[:50]  # Limit length
            
            if city_filter:
                # Single city CSV
                businesses = results['businesses_by_city'].get(city_filter, [])
                filename = f"businesses_{clean_keywords}_{city_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            else:
                # All businesses CSV
                businesses = []
                for city_businesses in results['businesses_by_city'].values():
                    businesses.extend(city_businesses)
                filename = f"search_{clean_keywords}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        if not businesses:
            flash('No businesses found to export', 'warning')
            return redirect(url_for('business_search_results', session_id=session_id))
        
        # Prepare CSV data
        output = io.StringIO()
        
        # Write CSV for web search results
        fieldnames = [
            'Title', 'URL', 'Description', 'Domain', 'Rank', 
            'Keywords Found', 'Search Date'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for business in businesses:
            # Extract the CSV-specific fields from the business data
            transformed_business = {
                'Title': business.get('Business Name', ''),
                'URL': business.get('Website', ''),
                'Description': business.get('Address', ''),  # Web descriptions stored in address field
                'Domain': business.get('Website', '').replace('https://', '').replace('http://', '').split('/')[0] if business.get('Website') else '',
                'Rank': '',  # Not available in current data
                'Keywords Found': business.get('Keywords Found', ''),
                'Search Date': business.get('Search Date', '')
            }
            writer.writerow(transformed_business)
        
        # Prepare response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response

    @app.route('/download-keyword-csv/<int:session_id>')
    @client_required
    def download_keyword_csv(session_id):
        """Download CSV for a specific keyword search session"""
        from business_search_service import business_search_service
        from models import BusinessData, BusinessSearchSession
        import csv
        import io
        
        # Get the child session (keyword-specific session)
        session = BusinessSearchSession.query.filter_by(
            id=session_id, user_id=current_user.id
        ).first()
        
        if not session:
            flash('Session not found', 'error')
            return redirect(url_for('business_search'))
        
        # Get businesses for this specific keyword session
        businesses = BusinessData.query.filter_by(session_id=session_id).all()
        
        if not businesses:
            flash('No results found for this keyword', 'warning')
            return redirect(url_for('business_search_results', session_id=session.parent_session_id or session_id))
        
        # Prepare CSV data
        output = io.StringIO()
        
        # Clean keyword for filename
        clean_keyword = session.keywords.replace(' ', '_').replace('\n', '_')
        clean_keyword = ''.join(c for c in clean_keyword if c.isalnum() or c in '_-')[:30]
        filename = f"keyword_{clean_keyword}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        # Write CSV
        fieldnames = [
            'Business Name', 'Website URL', 'Description', 'Phone', 'Rating',
            'Keywords Found', 'Search Date'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for business in businesses:
            writer.writerow({
                'Business Name': business.name,
                'Website URL': business.website,
                'Description': business.address,  # We use address field for description/snippet
                'Phone': business.phone or '',
                'Rating': business.rating or '',
                'Keywords Found': business.keywords_searched,
                'Search Date': business.created_at.strftime('%Y-%m-%d %H:%M:%S') if business.created_at else ''
            })
        
        # Prepare response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response

    @app.route('/delete-business-search-session/<int:session_id>', methods=['POST'])
    @client_required
    def delete_business_search_session(session_id):
        """Delete a business search session and all associated data"""
        from models import BusinessSearchSession, BusinessData
        
        # Get the session - verify it belongs to current user
        session = BusinessSearchSession.query.filter_by(
            id=session_id, user_id=current_user.id
        ).first()
        
        if not session:
            flash('Search session not found or access denied', 'error')
            return redirect(url_for('business_search'))
        
        try:
            # Get session info for flash message
            keywords = session.keywords
            total_businesses = session.total_businesses_found or 0
            
            # Check if this is a parent session with child sessions
            child_sessions = BusinessSearchSession.query.filter_by(parent_session_id=session_id).all()
            
            if child_sessions:
                # Delete all child sessions and their business data
                for child_session in child_sessions:
                    BusinessData.query.filter_by(session_id=child_session.id).delete()
                    db.session.delete(child_session)
            
            # Delete business data for this session
            BusinessData.query.filter_by(session_id=session_id).delete()
            
            # Delete the main session
            db.session.delete(session)
            db.session.commit()
            
            flash(f'Successfully deleted search for "{keywords}" with {total_businesses} results', 'success')
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting session {session_id}: {str(e)}")
            flash('Error deleting search session. Please try again.', 'error')
        
        return redirect(url_for('business_search'))

    @app.route('/delete-all-business-searches', methods=['POST'])
    @client_required
    def delete_all_business_searches():
        """Delete all business search sessions for the current user"""
        from models import BusinessSearchSession, BusinessData
        
        try:
            # Get all sessions for the current user
            user_sessions = BusinessSearchSession.query.filter_by(user_id=current_user.id).all()
            
            if not user_sessions:
                flash('No searches found to delete', 'info')
                return redirect(url_for('business_search'))
            
            total_sessions = len(user_sessions)
            total_businesses = 0
            
            # Count total businesses that will be deleted
            for session in user_sessions:
                total_businesses += BusinessData.query.filter_by(session_id=session.id).count()
            
            # Delete all business data for user sessions
            for session in user_sessions:
                BusinessData.query.filter_by(session_id=session.id).delete()
            
            # Delete all user sessions
            BusinessSearchSession.query.filter_by(user_id=current_user.id).delete()
            
            db.session.commit()
            
            flash(f'Successfully deleted all {total_sessions} searches with {total_businesses} total results', 'success')
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting all sessions for user {current_user.id}: {str(e)}")
            flash('Error deleting all searches. Please try again.', 'error')
        
        return redirect(url_for('business_search'))

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)