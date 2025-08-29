from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from enum import Enum
import json

db = SQLAlchemy()

class UserRole(Enum):
    ADMIN = "ADMIN"
    CLIENT = "CLIENT"

class APIKeyStatus(Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    FAILED = "FAILED"

class TransactionStatus(Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.CLIENT)
    coins = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    user_active = db.Column(db.Boolean, default=True)
    
    # Free trial coins for new users
    trial_coins_used = db.Column(db.Boolean, default=False)
    
    # Relationships
    transactions = db.relationship('CoinTransaction', foreign_keys='CoinTransaction.user_id', backref='user', lazy=True)
    processed_transactions = db.relationship('CoinTransaction', foreign_keys='CoinTransaction.processed_by', backref='processed_by_admin', lazy=True)
    searches = db.relationship('SearchHistory', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    def add_coins(self, amount, transaction_type="purchase"):
        self.coins += amount
        transaction = CoinTransaction()
        transaction.user_id = self.id
        transaction.amount = amount
        transaction.transaction_type = transaction_type
        transaction.status = TransactionStatus.COMPLETED
        db.session.add(transaction)
    
    def deduct_coins(self, amount, transaction_type="search"):
        if self.coins >= amount:
            self.coins -= amount
            transaction = CoinTransaction()
            transaction.user_id = self.id
            transaction.amount = -amount
            transaction.transaction_type = transaction_type
            transaction.status = TransactionStatus.COMPLETED
            db.session.add(transaction)
            return True
        return False

class APIKey(db.Model):
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(100), nullable=False)
    key_value = db.Column(db.String(200), nullable=False)
    status = db.Column(db.Enum(APIKeyStatus), default=APIKeyStatus.ACTIVE)
    usage_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    last_used = db.Column(db.DateTime)
    last_error = db.Column(db.DateTime)
    daily_limit = db.Column(db.Integer, default=2500)  # Serper.dev free tier limit
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Credit monitoring fields
    total_credits = db.Column(db.Integer, default=2500)  # Total credits allocated for this key
    credits_used = db.Column(db.Integer, default=0)  # Credits used so far
    last_credit_check = db.Column(db.DateTime)  # Last time credits were updated
    low_credit_alerted = db.Column(db.Boolean, default=False)  # Has low credit alert been sent
    
    def __repr__(self):
        return f'<APIKey {self.key_name}>'
    
    def record_usage(self, success=True):
        self.usage_count += 1
        self.last_used = datetime.utcnow()
        if success:
            self.credits_used += 1  # Only count successful requests as credits used
        if not success:
            self.error_count += 1
            self.last_error = datetime.utcnow()
    
    @property
    def remaining_credits(self):
        """Calculate estimated remaining credits"""
        return max(0, self.total_credits - self.credits_used)
    
    @property  
    def credits_percentage(self):
        """Get percentage of credits remaining"""
        if self.total_credits == 0:
            return 0
        return (self.remaining_credits / self.total_credits) * 100
    
    @property
    def is_low_credits(self):
        """Check if credits are below 500 (warning threshold)"""
        return self.remaining_credits < 500
    
    @property
    def priority_score(self):
        """Calculate priority score for API rotation (higher = use first)"""
        # Prioritize keys with more remaining credits
        base_score = self.remaining_credits
        # Bonus for less recent usage (spread load)
        if self.last_used:
            hours_since_use = (datetime.utcnow() - self.last_used).total_seconds() / 3600
            base_score += min(hours_since_use * 10, 100)  # Cap bonus at 100
        return base_score

class CoinTransaction(db.Model):
    __tablename__ = 'coin_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # Positive for purchase, negative for usage
    transaction_type = db.Column(db.String(50), nullable=False)  # purchase, search, refund, admin_adjustment, manual_payment
    status = db.Column(db.Enum(TransactionStatus), default=TransactionStatus.PENDING)
    stripe_payment_id = db.Column(db.String(200))
    payment_method = db.Column(db.String(50))  # stripe, bank_transfer, paypal, crypto, other
    payment_notes = db.Column(db.Text)  # Payment reference, transaction ID, etc.
    admin_notes = db.Column(db.Text)  # Admin notes for approval/rejection
    processed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Admin who processed
    processed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<CoinTransaction {self.user_id}: {self.amount}>'

class SearchHistory(db.Model):
    __tablename__ = 'search_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    keywords = db.Column(db.Text, nullable=False)
    results_json = db.Column(db.Text)  # Store results as JSON
    coins_used = db.Column(db.Integer, default=1)
    api_key_used = db.Column(db.String(100))
    search_duration = db.Column(db.Float)  # in seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    session_id = db.Column(db.Integer, db.ForeignKey('search_sessions.id'), nullable=True)
    
    def __repr__(self):
        return f'<SearchHistory {self.user_id}: {self.keywords[:50]}>'
    
    def get_results(self):
        if self.results_json:
            return json.loads(self.results_json)
        return []
    
    def set_results(self, results):
        self.results_json = json.dumps(results)


class SearchSession(db.Model):
    __tablename__ = 'search_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_keywords = db.Column(db.Integer, nullable=False)
    total_results = db.Column(db.Integer, default=0)
    upgrade_results = db.Column(db.Integer, default=0)
    keyword_list = db.Column(db.Text)  # Original keyword input
    status = db.Column(db.String(20), default='processing')  # processing, completed, failed
    progress = db.Column(db.Float, default=0.0)  # Progress percentage
    current_keyword = db.Column(db.String(200))  # Currently processing keyword
    processing_time = db.Column(db.Float)  # Total processing time in seconds
    max_results = db.Column(db.Integer, default=10)  # Google search result limit
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref='search_sessions')
    searches = db.relationship('SearchHistory', backref='session', foreign_keys='SearchHistory.session_id')
    
    def __repr__(self):
        return f'<SearchSession {self.user_id}: {self.total_keywords} keywords>'

class PricingPackage(db.Model):
    __tablename__ = 'pricing_packages'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    coins = db.Column(db.Integer, nullable=False)
    price_cents = db.Column(db.Integer, nullable=False)  # Price in cents
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def price_dollars(self):
        return self.price_cents / 100
    
    def __repr__(self):
        return f'<PricingPackage {self.name}: {self.coins} coins for ${self.price_dollars}>'

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), nullable=False)  # info, warning, error
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_keys.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<SystemLog {self.level}: {self.message[:50]}>'

class PaymentMethodType(Enum):
    STRIPE = "STRIPE"
    PAYPAL = "PAYPAL"

class PaymentMethod(db.Model):
    __tablename__ = 'payment_methods'
    
    id = db.Column(db.Integer, primary_key=True)
    method_type = db.Column(db.Enum(PaymentMethodType), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Stripe configuration
    stripe_public_key = db.Column(db.String(200))
    stripe_secret_key = db.Column(db.String(200))
    stripe_webhook_secret = db.Column(db.String(200))
    
    # PayPal configuration
    paypal_email = db.Column(db.String(120))
    paypal_instructions = db.Column(db.Text)
    
    def __repr__(self):
        return f'<PaymentMethod {self.name}: {self.method_type.value}>'
    
    def get_config(self):
        """Get configuration dict for this payment method"""
        if self.method_type == PaymentMethodType.STRIPE:
            return {
                'public_key': self.stripe_public_key,
                'secret_key': self.stripe_secret_key,
                'webhook_secret': self.stripe_webhook_secret
            }
        elif self.method_type == PaymentMethodType.PAYPAL:
            return {
                'email': self.paypal_email,
                'instructions': self.paypal_instructions
            }

class SMTPSettings(db.Model):
    __tablename__ = 'smtp_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(200), nullable=False, default='smtp.gmail.com')
    smtp_port = db.Column(db.Integer, nullable=False, default=587)
    smtp_username = db.Column(db.String(200), nullable=False)
    smtp_password = db.Column(db.String(200), nullable=False)
    sender_email = db.Column(db.String(200), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False, default='Domain Upgrade Pro')
    admin_email = db.Column(db.String(200), nullable=False)  # Email to receive notifications
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SMTPSettings {self.sender_email}>'

class ContactForm(db.Model):
    __tablename__ = 'contact_forms'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ContactForm {self.name} - {self.subject}>'