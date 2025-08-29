from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
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
from models import db, User, APIKey, CoinTransaction, SearchHistory, SearchSession, PricingPackage, SystemLog, UserRole, APIKeyStatus, TransactionStatus
from config import Config
from auth_utils import bcrypt, login_manager, admin_required, client_required, hash_password, check_password
from api_rotation import EnhancedDomainAnalyzer
from utils import parse_domain_list

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
    
    # Initialize domain analyzer
    app.domain_analyzer = EnhancedDomainAnalyzer()
    
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
    
    # Authentication routes
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
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
        
        # Get API key stats
        api_keys = APIKey.query.all()
        
        # Recent activity
        recent_searches = SearchHistory.query.order_by(SearchHistory.created_at.desc()).limit(10).all()
        recent_users = User.query.filter_by(role=UserRole.CLIENT).order_by(User.created_at.desc()).limit(10).all()
        
        return render_template('admin/dashboard.html',
                             total_users=total_users,
                             total_searches=total_searches,
                             total_revenue=total_revenue,
                             api_keys=api_keys,
                             recent_searches=recent_searches,
                             recent_users=recent_users)
    
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
        
        api_key = APIKey()
        api_key.key_name = key_name
        api_key.key_value = key_value
        api_key.daily_limit = daily_limit
        api_key.status = APIKeyStatus.ACTIVE
        
        db.session.add(api_key)
        db.session.commit()
        
        flash('API key added successfully', 'success')
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
    
    # Client Dashboard Routes
    @app.route('/dashboard')
    @client_required
    def client_dashboard():
        # Get user's search history
        recent_searches = SearchHistory.query.filter_by(user_id=current_user.id).order_by(
            SearchHistory.created_at.desc()).limit(5).all()
        
        # Get user's transaction history
        recent_transactions = CoinTransaction.query.filter_by(user_id=current_user.id).order_by(
            CoinTransaction.created_at.desc()).limit(5).all()
        
        return render_template('client/dashboard.html',
                             user=current_user,
                             recent_searches=recent_searches,
                             recent_transactions=recent_transactions)
    
    @app.route('/search', methods=['GET', 'POST'])
    @client_required
    def search():
        if request.method == 'POST':
            # Check if user has enough coins
            if current_user.coins < 1:
                flash('You need at least 1 coin to perform a search. Please purchase more coins.', 'error')
                return redirect(url_for('buy_coins'))
            
            # Get input
            keywords_input = request.form.get('keywords', '').strip()
            if not keywords_input:
                flash('Please enter keywords to search', 'error')
                return render_template('client/search.html')
            
            # Parse keywords (one set per line)
            keyword_sets = parse_domain_list(keywords_input)
            
            if not keyword_sets:
                flash('Please enter valid keywords', 'error')
                return render_template('client/search.html')
            
            # Check if user has enough coins for all searches
            total_searches = len(keyword_sets)
            if current_user.coins < total_searches:
                flash(f'You need {total_searches} coins for this search but only have {current_user.coins} coins.', 'error')
                return redirect(url_for('buy_coins'))
            
            # Check for bulk processing limits
            max_bulk_keywords = 500  # Configurable limit
            if total_searches > max_bulk_keywords:
                flash(f'Maximum {max_bulk_keywords} keywords allowed per search session. You entered {total_searches} keywords.', 'error')
                return render_template('client/search.html')
            
            # For bulk processing, redirect to processor
            if total_searches > 10:  # Use bulk processing for more than 10 keywords
                session['pending_keywords'] = keywords_input
                session['pending_total'] = total_searches
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
                db.session.add(search_session)
                db.session.flush()
                
                for keywords in keyword_sets:
                    # Deduct coin for this search
                    if not current_user.deduct_coins(1, 'search'):
                        flash('Insufficient coins', 'error')
                        break
                    
                    # Perform search
                    search_start = datetime.utcnow()
                    results, api_key_used = app.domain_analyzer.analyze_keywords(keywords)
                    search_duration = (datetime.utcnow() - search_start).total_seconds()
                    
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
                
                if all_results:
                    # Filter results for UI display (only show upgrade opportunities)
                    upgrade_results = [r for r in all_results if r.get('Is_Upgrade', False)]
                    
                    # Store search ID for downloads instead of full data in session
                    latest_search = SearchHistory.query.filter_by(user_id=current_user.id).order_by(
                        SearchHistory.created_at.desc()).first()
                    session['latest_search_id'] = latest_search.id if latest_search else None
                    
                    # Show success message based on upgrade opportunities
                    total_count = len(all_results)
                    upgrade_count = len(upgrade_results)
                    
                    if upgrade_count > 0:
                        flash(f'Search completed! Found {upgrade_count} upgrade opportunities out of {total_count} total results.', 'success')
                    else:
                        flash(f'Search completed! Found {total_count} potential matches but no clear upgrade opportunities.', 'info')
                    
                    # Update the search session with final statistics
                    search_session = SearchSession.query.get(session['current_session_id'])
                    search_session.total_results = total_count
                    search_session.upgrade_results = upgrade_count
                    
                    db.session.commit()
                    
                    # Redirect to the search session page
                    return redirect(url_for('view_search_session', session_id=search_session.id))
                else:
                    flash('No results found for your keywords.', 'info')
                    return render_template('client/search.html')
                
            except Exception as e:
                flash(f'Search error: {str(e)}', 'error')
                return render_template('client/search.html')
        
        return render_template('client/search.html')
    
    @app.route('/bulk-search-processor')
    @client_required
    def bulk_search_processor():
        keywords_input = session.get('pending_keywords', '')
        total_keywords = session.get('pending_total', 0)
        
        if not keywords_input or not total_keywords:
            flash('Invalid search parameters', 'error')
            return redirect(url_for('search'))
        
        # Clear session data
        session.pop('pending_keywords', None)
        session.pop('pending_total', None)
        
        # Create search session
        search_session = SearchSession()
        search_session.user_id = current_user.id
        search_session.total_keywords = total_keywords
        search_session.keyword_list = keywords_input
        search_session.status = 'processing'
        
        db.session.add(search_session)
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
            
            # Check and deduct coins upfront
            total_cost = len(keyword_sets)
            if current_user.coins < total_cost:
                search_session.status = 'failed'
                db.session.commit()
                return jsonify({'error': 'Insufficient coins'}), 400
            
            # Deduct all coins at once
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
            
            # Use bulk search with progress tracking
            bulk_results = app.domain_analyzer.api_rotation.search_google_bulk(
                keyword_sets, progress_callback=update_progress
            )
            
            # Process results and save to database in batches
            batch_histories = []
            for keywords, results, api_key_used in bulk_results:
                search_history = SearchHistory()
                search_history.user_id = current_user.id
                search_history.keywords = keywords
                search_history.set_results(results)
                search_history.api_key_used = api_key_used
                search_history.session_id = session_id
                
                batch_histories.append(search_history)
                all_results.extend(results)
                
                # Batch insert every 50 records
                if len(batch_histories) >= 50:
                    db.session.add_all(batch_histories)
                    db.session.commit()
                    batch_histories = []
            
            # Insert remaining records
            if batch_histories:
                db.session.add_all(batch_histories)
            
            # Update session with final results
            processing_end = datetime.utcnow()
            search_session.total_results = len(all_results)
            search_session.upgrade_results = len([r for r in all_results if r.get('Is_Upgrade', False)])
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
    def download_results(format):
        # Get results from the most recent search
        search_id = session.get('latest_search_id')
        if not search_id:
            flash('No recent search results to download', 'error')
            return redirect(url_for('search'))
        
        # Get all results from recent searches for this user
        recent_searches = SearchHistory.query.filter_by(user_id=current_user.id).order_by(
            SearchHistory.created_at.desc()).limit(10).all()
        
        results = []
        for search in recent_searches:
            search_results = search.get_results()
            if search_results:
                results.extend(search_results)
        
        if not results:
            flash('No search results to download', 'error')
            return redirect(url_for('search'))
        
        df = pd.DataFrame(results)
        
        if format == 'csv':
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)
            csv_data = csv_buffer.getvalue()
            
            return Response(
                csv_data,
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=keyword_upgrade_opportunities.csv'}
            )
        
        elif format == 'excel':
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Upgrade Opportunities', index=False)
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
    
    @app.route('/buy-coins')
    @client_required
    def buy_coins():
        packages = PricingPackage.query.filter_by(is_active=True).all()
        return render_template('client/buy_coins.html', packages=packages, 
                             stripe_public_key=app.config['STRIPE_PUBLIC_KEY'])
    
    @app.route('/create-payment-intent', methods=['POST'])
    @client_required
    def create_payment_intent():
        package_id = request.json.get('package_id')
        package = PricingPackage.query.get_or_404(package_id)
        
        try:
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
        upgrade_results = []
        for search in searches:
            results = search.get_results()
            if results:
                all_results.extend(results)
                upgrade_results.extend([r for r in results if r.get('Is_Upgrade', False)])
        
        return render_template('client/search_session.html',
                             session=search_session,
                             searches=searches,
                             all_results=all_results,
                             upgrade_results=upgrade_results)
    
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
        
        # Get all results from this session
        searches = SearchHistory.query.filter_by(session_id=session_id).all()
        results = []
        for search in searches:
            search_results = search.get_results()
            if search_results:
                results.extend(search_results)
        
        if not results:
            flash('No results to download for this search session', 'error')
            return redirect(url_for('view_search_session', session_id=session_id))
        
        df = pd.DataFrame(results)
        timestamp = search_session.created_at.strftime('%Y%m%d_%H%M%S')
        
        if format == 'csv':
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)
            csv_data = csv_buffer.getvalue()
            
            return Response(
                csv_data,
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=search_session_{session_id}_{timestamp}.csv'}
            )
        
        elif format == 'excel':
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Search Results', index=False)
            excel_data = excel_buffer.getvalue()
            
            return Response(
                excel_data,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                headers={'Content-Disposition': f'attachment; filename=search_session_{session_id}_{timestamp}.xlsx'}
            )
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)