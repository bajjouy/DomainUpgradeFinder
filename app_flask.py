from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
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
    login_manager.login_view = 'auth.login'
    
    migrate = Migrate(app, db)
    
    # Configure Stripe
    stripe.api_key = app.config['STRIPE_SECRET_KEY']
    
    # Configure PayPal (Sandbox credentials for testing)
    app.config['PAYPAL_CLIENT_ID'] = os.getenv('PAYPAL_CLIENT_ID', 'AeHNHxV_vMG8O8_Vs-QPHgmJbfHdHFRHSAYKP2dOZjVMy8ZVfz8E-GzuWDqJOPi4oUzXmKcV_f7qlE3m')
    app.config['PAYPAL_CLIENT_SECRET'] = os.getenv('PAYPAL_CLIENT_SECRET', 'EO5sAflAvkuzDMVaJi2zCwomZILCFx6_YNrtKOzKXUqw8L_7A4lF8QhYDHjlSHRCyLqc8NxW_z1GhZmY')
    app.config['PAYPAL_MODE'] = os.getenv('PAYPAL_MODE', 'sandbox')
    
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
        return render_template('index.html')
    
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
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            captcha = request.form.get('captcha', '').upper()
            captcha_answer = request.form.get('captcha_answer', '').upper()
            
            # Validate captcha first
            if captcha != captcha_answer:
                flash('Invalid security code. Please try again.', 'error')
                return render_template('login.html')
            
            user = User.query.filter_by(email=email).first()
            
            if user and check_password(user.password_hash, password):
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                if user.role == UserRole.ADMIN:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('client_dashboard'))
            else:
                flash('Invalid email or password', 'error')
        
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
    
    @app.route('/admin/api-keys')
    @admin_required
    def admin_api_keys():
        api_keys = APIKey.query.all()
        return render_template('admin/api_keys.html', api_keys=api_keys)
    
    @app.route('/admin/api-keys/add', methods=['POST'])
    @admin_required
    def add_api_key():
        key_name = request.form.get('key_name')
        key_value = request.form.get('key_value')
        daily_limit = int(request.form.get('daily_limit', 2500))
        
        total_credits = int(request.form.get('total_credits', 2500))
        
        api_key = APIKey()
        api_key.key_name = key_name
        api_key.key_value = key_value
        api_key.daily_limit = daily_limit
        api_key.total_credits = total_credits
        api_key.status = APIKeyStatus.ACTIVE
        
        db.session.add(api_key)
        db.session.commit()
        
        flash('API key added successfully', 'success')
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
        
        for i, key_value in enumerate(api_keys_list):
            try:
                # Generate sequential name
                key_name = f'api{max_num + i + 1}'
                
                # Check if key already exists
                existing_key = APIKey.query.filter_by(key_value=key_value).first()
                if existing_key:
                    skipped_count += 1
                    continue
                
                # Create new API key
                api_key = APIKey()
                api_key.key_name = key_name
                api_key.key_value = key_value
                api_key.daily_limit = bulk_daily_limit
                api_key.total_credits = bulk_total_credits
                api_key.status = APIKeyStatus.ACTIVE
                
                db.session.add(api_key)
                added_count += 1
                
            except Exception as e:
                errors.append(f'Key {i+1}: {str(e)}')
        
        try:
            db.session.commit()
            
            # Create success message
            success_msg = f'✅ Successfully imported {added_count} API keys'
            if skipped_count > 0:
                success_msg += f' (skipped {skipped_count} duplicates)'
            
            flash(success_msg, 'success')
            
            if errors:
                flash(f'⚠️ Some errors occurred: {"; ".join(errors[:3])}', 'warning')
                
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
    
    @app.route('/admin/users')
    @admin_required
    def admin_users():
        users = User.query.filter_by(role=UserRole.CLIENT).all()
        return render_template('admin/users.html', users=users)
    
    @app.route('/admin/users/<int:user_id>/coins', methods=['POST'])
    @admin_required
    def adjust_user_coins(user_id):
        user = User.query.get_or_404(user_id)
        amount = int(request.form.get('amount'))
        reason = request.form.get('reason', 'Admin adjustment')
        
        if amount > 0:
            user.add_coins(amount, 'admin_adjustment')
        else:
            user.deduct_coins(abs(amount), 'admin_adjustment')
        
        db.session.commit()
        flash(f'User coins adjusted by {amount}', 'success')
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
    def search():
        if request.method == 'POST':
            # Check if user has enough coins (skip for admin users)
            if current_user.role != UserRole.ADMIN and current_user.coins < 1:
                flash('You need at least 1 coin to perform a search. Please purchase more coins.', 'error')
                return redirect(url_for('buy_coins'))
            
            # Get input
            keywords_input = request.form.get('keywords', '').strip()
            # Use adaptive max_results - start with 100, reduce by 10 if fails
            max_results = 100  # Will be adaptive per search
            
            if not keywords_input:
                flash('Please enter keywords to search', 'error')
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
            max_bulk_keywords = 500  # Configurable limit
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
                
                # Add coins to user account
                current_user.add_coins(coins, 'purchase')
                db.session.commit()
                
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

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)