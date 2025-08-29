from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from enum import Enum
import json

db = SQLAlchemy()

class UserRole(Enum):
    ADMIN = "admin"
    CLIENT = "client"

class APIKeyStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"

class TransactionStatus(Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

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
    transactions = db.relationship('CoinTransaction', backref='user', lazy=True)
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
    
    def __repr__(self):
        return f'<APIKey {self.key_name}>'
    
    def record_usage(self, success=True):
        self.usage_count += 1
        self.last_used = datetime.utcnow()
        if not success:
            self.error_count += 1
            self.last_error = datetime.utcnow()

class CoinTransaction(db.Model):
    __tablename__ = 'coin_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # Positive for purchase, negative for usage
    transaction_type = db.Column(db.String(50), nullable=False)  # purchase, search, refund, admin_adjustment
    status = db.Column(db.Enum(TransactionStatus), default=TransactionStatus.PENDING)
    stripe_payment_id = db.Column(db.String(200))
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
    
    def __repr__(self):
        return f'<SearchHistory {self.user_id}: {self.keywords[:50]}>'
    
    def get_results(self):
        if self.results_json:
            return json.loads(self.results_json)
        return []
    
    def set_results(self, results):
        self.results_json = json.dumps(results)

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