# Amazon Bestseller Screenshot Monitor
# A web app to monitor Amazon products and capture bestseller screenshots

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, Blueprint, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import secrets
import flask 
import string
import sqlite3
import resend
import requests
from bs4 import BeautifulSoup, Tag
from bs4.element import NavigableString
import base64
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    print("⚠️  PIL not available, image processing disabled")
    PIL_AVAILABLE = False
    Image = None  # Explicitly set to None for type checker
import io
from datetime import datetime, timedelta
import threading
import time
import schedule
import re
import os
import atexit # For graceful shutdown
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    print("⚠️  PostgreSQL not available, using SQLite only")
    POSTGRES_AVAILABLE = False
    # Don't set psycopg2 to None to avoid type checker issues
from urllib.parse import urlparse
import json
import signal
import sys
import smtplib
import boto3
import hashlib
import stripe
from collections import OrderedDict
from botocore.exceptions import ClientError
from flask_talisman import Talisman
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formataddr
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    print("⚠️  Cryptography not available, encryption features disabled")
    CRYPTOGRAPHY_AVAILABLE = False
    # Don't set Fernet to None to avoid type checker issues
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

load_dotenv()
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

# ============= INITIALIZE FLASK APP FIRST =============
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# ============= BASIC APP CONFIGURATION =============
app.config['WTF_CSRF_ENABLED'] = os.environ.get('WTF_CSRF_ENABLED', 'true').lower() == 'true'
app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['DEBUG'] = False

# ============= INITIALIZE EXTENSIONS =============
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # Use in-memory storage
    strategy="fixed-window"
)

login_manager.login_view = 'auth.login'  # type: ignore
login_manager.login_message = 'Please log in to access this page.'
login_manager.session_protection = 'strong'  # Protect against session hijacking

login_manager.init_app(app)
csrf.init_app(app)
limiter.init_app(app)

# Create authentication blueprint
auth = Blueprint('auth', __name__)

# ============= GLOBAL VARIABLES =============
SCHEDULER_ENABLED = os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true'
scheduler_initialize = False
scheduler_thread = None
scheduler_running = False
scheduler_lock = threading.Lock()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# ============= CONFIGURATION VARIABLES =============
# Password requirements
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIREMENTS = {
    'min_length': 8,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digit': True,
    'require_special': True,
    'max_length': 128, #Prevent DoS attacks with excessively long passwords
}

# Email configuration from environment variables
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', SMTP_USERNAME)
SENDER_NAME = os.environ.get('SENDER_NAME', 'Amazon Screenshot Tracker')
resend.api_key = os.environ.get('RESEND_API_KEY')

# ScrapingBee configuration - using environment variables for security
SCRAPINGBEE_API_KEY = os.environ.get('SCRAPINGBEE_SECRET_KEY')
SCRAPINGBEE_URL = 'https://app.scrapingbee.com/api/v1/'
SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), 'screenshots')
if not os.path.exists(SCREENSHOT_DIR):
    os.makedirs(SCREENSHOT_DIR)

# Validate that the API key is available
if not SCRAPINGBEE_API_KEY:
    print("⚠️  WARNING: SCRAPINGBEE_API_KEY environment variable not set!")

# ============= SECURITY HEADERS (Production only) =============
if IS_PRODUCTION:
    talisman_config = {
        'force_https': False,
        'strict_transport_security': False,
        'content_security_policy': {
            'default-src': "'self'",
            'img-src': "'self' data: https:",
            'script-src': "'self' 'unsafe-inline'",
            'style-src': "'self' 'unsafe-inline'",
        },
        'session_cookie_secure': True,
        'session_cookie_http_only': True,
    }
    talisman = Talisman(app, **talisman_config)

# ============= LOGGING CONFIGURATION =============
if not app.debug:
    # Create logs directory
    if not os.path.exists('logs'):
        os.mkdir('logs')

    # Rotating file handler
    file_handler = RotatingFileHandler('logs/amazon_monitor.log',
                                     maxBytes=10240000,  # 10MB
                                     backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Amazon Bestseller Monitor startup')

# ============= DATABASE FUNCTIONS =============
def get_db():
    """Get database connection - PostgreSQL in production, SQLite in development"""
    database_url = os.environ.get('DATABASE_URL')

    if database_url and POSTGRES_AVAILABLE:
        # Production: PostgreSQL
        try:
            import psycopg2  # Re-import to satisfy type checker
            from psycopg2.extras import RealDictCursor
            conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
            return conn
        except Exception as e:
            print(f"❌ PostgreSQL connection failed: {e}")
            raise
    else:
        # Development: SQLite
        if database_url and not POSTGRES_AVAILABLE:
            print("⚠️  DATABASE_URL set but PostgreSQL not available, falling back to SQLite")
        conn = sqlite3.connect('amazon_monitor.db')
        conn.row_factory = sqlite3.Row
        return conn

def get_db_type():
    """Determine if using PostgreSQL or SQLite"""
    return 'postgresql' if os.environ.get('DATABASE_URL') and POSTGRES_AVAILABLE else 'sqlite'

# ============= SCHEDULER FUNCTIONS =============
def ensure_scheduler_running():
    """Ensure scheduler is running - thread-safe"""
    global scheduler_initialized, scheduler_thread, scheduler_running, scheduler_lock

    # Safety check - initialize if not exists
    if 'scheduler_initialized' not in globals():
        globals()['scheduler_initialized'] = False
    if 'scheduler_thread' not in globals():
        globals()['scheduler_thread'] = None
    if 'scheduler_running' not in globals():
        globals()['scheduler_running'] = False
    if 'scheduler_lock' not in globals():
        globals()['scheduler_lock'] = threading.Lock()

    with scheduler_lock:
        if scheduler_initialized and scheduler_thread and scheduler_thread.is_alive():
            return True

        scheduler_enabled = os.environ.get('ENABLE_SCHEDULER', 'true').lower() == 'true'

        if not scheduler_enabled:
            print("⚠️ Scheduler disabled via ENABLE_SCHEDULER environment variable")
            return False

        print("🚀 Starting scheduler thread...")

        try:
            scheduler_thread = threading.Thread(
                target=run_scheduler,
                daemon=True,
                name="PerProductScheduler"
            )
            scheduler_thread.start()

            time.sleep(2)

            if scheduler_thread.is_alive():
                scheduler_running = True
                scheduler_initialized = True
                print("✅ Scheduler thread started successfully!")
                return True
            else:
                scheduler_running = False
                print("❌ Scheduler thread failed to start!")
                return False

        except Exception as e:
            print(f"❌ Error starting scheduler: {e}")
            import traceback
            traceback.print_exc()
            scheduler_running = False
            return False

def run_scheduler():
    """Per-product intelligent scheduler - checks each product 60 minutes after last check"""
    global scheduler_running, scheduler_initialized, scheduler_thread

    print("🎯 Intelligent Per-Product Scheduler Started")
    print("📊 Each product will be checked 60 minutes after its last check")

    scheduler_running = True
    consecutive_errors = 0
    max_consecutive_errors = 5

    while scheduler_running:
        try:
            if not os.environ.get('ENABLE_SCHEDULER', 'true').lower() == 'true':
                print("🛑 Scheduler disabled via environment variable")
                break

            products_checked = check_due_products()

            if products_checked >= 0:
                consecutive_errors = 0

            for i in range(60):
                if not scheduler_running:
                    break
                time.sleep(1)

        except Exception as e:
            consecutive_errors += 1
            print(f"❌ Scheduler error ({consecutive_errors}/{max_consecutive_errors}): {e}")
            import traceback
            traceback.print_exc()

            if consecutive_errors >= max_consecutive_errors:
                print("❌ Too many consecutive errors, stopping scheduler")
                break

            time.sleep(300)

    print("📅 Scheduler stopped")
    scheduler_running = False

def check_due_products():
    """Check products that are due for their hourly check"""
    current_time = datetime.now()
    check_threshold = current_time - timedelta(minutes=60)

    conn = None
    products_checked = 0

    try:
        conn = get_db()
        cursor = conn.cursor()

        # Find products that haven't been checked in the last 60 minutes
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT 
                    p.id as product_id,
                    p.product_url,
                    p.product_title,
                    p.current_rank,
                    p.current_category,
                    p.is_bestseller,
                    p.last_checked,
                    p.created_at,
                    p.user_id,
                    u.email,
                    u.scrapingbee_api_key
                FROM products p
                JOIN users u ON p.user_id = u.id
                WHERE p.active = true
                  AND u.scrapingbee_api_key IS NOT NULL
                  AND (
                      p.last_checked IS NULL 
                      OR p.last_checked <= %s
                  )
                ORDER BY 
                    COALESCE(p.last_checked, p.created_at) ASC
                LIMIT 10
            ''', (check_threshold,))
        else:
            cursor.execute('''
                SELECT 
                    p.id as product_id,
                    p.product_url,
                    p.product_title,
                    p.current_rank,
                    p.current_category,
                    p.is_bestseller,
                    p.last_checked,
                    p.created_at,
                    p.user_id,
                    u.email,
                    u.scrapingbee_api_key
                FROM products p
                JOIN users u ON p.user_id = u.id
                WHERE p.active = 1
                  AND u.scrapingbee_api_key IS NOT NULL
                  AND (
                      p.last_checked IS NULL 
                      OR p.last_checked <= ?
                  )
                ORDER BY 
                    COALESCE(p.last_checked, p.created_at) ASC
                LIMIT 10
            ''', (check_threshold,))

        due_products = cursor.fetchall()

        if not due_products:
            conn.close()
            return 0

        print(f"\n⏰ {current_time.strftime('%H:%M:%S')} - Found {len(due_products)} products due for checking")

        # Process each product
        for product in due_products:
            # Extract product data
            if isinstance(product, dict):
                product_id = product['product_id']
                url = product['product_url']
                title = product['product_title']
                user_id = product['user_id']
                category = product['current_category']
            else:
                product_id = product[0]
                url = product[1]
                title = product[2]
                user_id = product[8]
                category = product[4]

            # Use the new check_single_product function
            success = check_single_product(
                product_id, url, user_id, title, category, None
            )

            if success:
                products_checked += 1

            time.sleep(2)  # Rate limiting between products

        # Close connection and return success count
        conn.close()
        return products_checked

    except Exception as e:
        print(f"❌ Database error in check_due_products: {e}")
        import traceback
        traceback.print_exc()

        if conn:
            try:
                conn.rollback()
                conn.close()
            except Exception as e:
                pass
        return -1

# ============= REQUEST HANDLERS =============

# ============= HEALTH CHECK ENDPOINT =============
@csrf.exempt
@app.route('/health')
def health_check():
    """Health check endpoint that doesn't fail due to scheduler"""
    try:
        return "OK", 200
    except Exception as e:
        return "OK", 200  # Always return OK to prevent restart loops

# ============= SIGNAL HANDLERS =============
def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    global scheduler_running
    print('🛑 Shutdown signal received, stopping scheduler...')
    scheduler_running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ============= CLASS DEFINITIONS =============
class DatabaseManager:
    def __init__(self):
        # Only initialize if tables don't exist
        self.init_db_if_needed()

    def get_db_type(self):
        """Determine if using PostgreSQL or SQLite"""
        return 'postgresql' if os.environ.get('DATABASE_URL') and POSTGRES_AVAILABLE else 'sqlite'

    def init_db_if_needed(self):
        """Only create tables if they don't exist - preserve data"""
        print("🔧 Checking database state...")
        conn = get_db()
        cursor = conn.cursor()
        db_type = self.get_db_type()

        try:
            if db_type == 'postgresql':
                # Check if users table exists
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = 'users'
                    )
                """)
                result = cursor.fetchone()

                if result is None:
                    table_exists = False
                elif isinstance(result, dict):
                    table_exists = result['exists']
                else:
                    table_exists = result[0]

                if not table_exists:
                    print("🔧 Tables don't exist, creating...")
                    self.create_postgresql_tables(cursor)
                    conn.commit()
                else:
                    print("✅ Tables already exist, preserving data")
                    # Just ensure all columns exist
                    self.ensure_columns_exist(cursor)
                    conn.commit()
            else:
                # SQLite for development
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='users'
                """)
                if not cursor.fetchone():
                    self.create_sqlite_tables(cursor)
                    conn.commit()
        except Exception as e:
            print(f"❌ Error in init_db_if_needed: {e}")
            import traceback
            traceback.print_exc()
            raise
        finally:
            conn.close()

    def ensure_columns_exist(self, cursor):
        """Add any missing columns without destroying data"""
        # Only add columns that might be missing
        self.add_column_if_not_exists(cursor, 'users', 'scrapingbee_api_key', 'TEXT')

    def add_column_if_not_exists(self, cursor, table_name, column_name, column_type):
        """Safely add column if it doesn't exist"""
        try:
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = %s AND column_name = %s
            """, (table_name, column_name))

            result = cursor.fetchone()
            if not result:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                print(f"✅ Added column {column_name} to {table_name}")
            else:
                print(f"✅ Column {column_name} already exists in {table_name}")
        except Exception as e:
            print(f"⚠️ Error adding column {column_name}: {e}")

    def create_postgresql_tables(self, cursor):
        """Create tables optimized for PostgreSQL"""

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(255),
                is_verified BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                verification_token VARCHAR(255),
                verification_token_expiry TIMESTAMP,
                reset_token VARCHAR(255),
                reset_token_expiry TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                last_failed_login TIMESTAMP,
                account_locked_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                two_factor_secret VARCHAR(255),
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                max_products INTEGER DEFAULT 10,
                notification_preferences VARCHAR(50) DEFAULT 'instant',
                scrapingbee_api_key TEXT
            )
        ''')

        self.add_column_if_not_exists(cursor, 'users', 'scrapingbee_api_key', 'TEXT')

        # Products table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                user_email VARCHAR(255) NOT NULL,
                product_url TEXT NOT NULL,
                product_title TEXT,
                current_rank VARCHAR(50),
                current_category TEXT,
                is_bestseller BOOLEAN DEFAULT FALSE,
                last_checked TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT TRUE
            )
        ''')

        # Rankings history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rankings (
                id SERIAL PRIMARY KEY,
                product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
                rank_number INTEGER,
                category TEXT,
                is_bestseller BOOLEAN,
                screenshot_data TEXT,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Screenshots table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bestseller_screenshots (
                id SERIAL PRIMARY KEY,
                product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
                screenshot_data TEXT,
                rank_achieved VARCHAR(50),
                category TEXT,
                achieved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Target categories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_categories (
                id SERIAL PRIMARY KEY,
                product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
                category_name VARCHAR(255) NOT NULL,
                target_rank INTEGER DEFAULT 1,
                best_rank_achieved INTEGER,
                is_achieved BOOLEAN DEFAULT FALSE,
                date_achieved TIMESTAMP,
                screenshot_id INTEGER REFERENCES bestseller_screenshots(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Baseline screenshots table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline_screenshots (
                id SERIAL PRIMARY KEY,
                product_id INTEGER UNIQUE REFERENCES products(id) ON DELETE CASCADE,
                screenshot_data TEXT,
                initial_rank VARCHAR(50),
                initial_category TEXT,
                captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Login history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                ip_address INET,
                user_agent TEXT,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN
            )
        ''')

        # Email verifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_verifications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                token VARCHAR(255) UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used BOOLEAN DEFAULT FALSE
            )
        ''')

        # User sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                session_token VARCHAR(255) UNIQUE,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Feedback table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                user_email VARCHAR(255),
                rating INTEGER,
                love TEXT,
                improve TEXT,
                bugs TEXT,
                would_pay VARCHAR(50),
                price_point VARCHAR(50),
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create indexes for better performance
        self.create_postgresql_indexes(cursor)

    def create_postgresql_indexes(self, cursor):
        """Create indexes for better query performance"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_products_user_id ON products(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_products_user_email ON products(user_email)",
            "CREATE INDEX IF NOT EXISTS idx_products_active ON products(active)",
            "CREATE INDEX IF NOT EXISTS idx_rankings_product_id ON rankings(product_id)",
            "CREATE INDEX IF NOT EXISTS idx_rankings_checked_at ON rankings(checked_at)",
            "CREATE INDEX IF NOT EXISTS idx_bestseller_screenshots_product_id ON bestseller_screenshots(product_id)",
            "CREATE INDEX IF NOT EXISTS idx_target_categories_product_id ON target_categories(product_id)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_login_history_user_id ON login_history(user_id)"
        ]

        for index_query in indexes:
            try:
                cursor.execute(index_query)
            except Exception as e:
                print(f"⚠️ Index creation warning: {e}")

    def add_achievement_tracking_columns(self):
        """Add columns needed for two-call strategy"""
        conn = get_db()
        cursor = conn.cursor()

        try:
            if get_db_type() == 'postgresql':
                cursor.execute("""
                    ALTER TABLE products 
                    ADD COLUMN IF NOT EXISTS last_rank INTEGER,
                    ADD COLUMN IF NOT EXISTS has_bestseller_badge BOOLEAN DEFAULT FALSE,
                    ADD COLUMN IF NOT EXISTS baseline_rank INTEGER,
                    ADD COLUMN IF NOT EXISTS last_achievement_date TIMESTAMP
                """)
            else:
                # SQLite - add columns one by one
                columns_to_add = [
                    ('last_rank', 'INTEGER'),
                    ('has_bestseller_badge', 'BOOLEAN DEFAULT 0'),
                    ('baseline_rank', 'INTEGER'),
                    ('last_achievement_date', 'TIMESTAMP')
                ]

                for column_name, column_type in columns_to_add:
                    try:
                        cursor.execute(f"ALTER TABLE products ADD COLUMN {column_name} {column_type}")
                        print(f"✅ Added column {column_name}")
                    except Exception as e:
                        if 'duplicate column' in str(e).lower():
                            print(f"✅ Column {column_name} already exists")
                        else:
                            print(f"⚠️ Error adding column {column_name}: {e}")

            conn.commit()
            print("✅ Achievement tracking columns added/verified")
        except Exception as e:
            print(f"⚠️ Error adding achievement columns: {e}")
        finally:
            conn.close()

    def create_sqlite_tables(self, cursor):
        """Create all SQLite tables with complete schema for development"""

        # Users table - COMPLETE schema with all columns from the start
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                is_verified BOOLEAN DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                verification_token TEXT,
                verification_token_expiry TIMESTAMP,
                reset_token TEXT,
                reset_token_expiry TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                last_failed_login TIMESTAMP,
                account_locked_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                two_factor_secret TEXT,
                two_factor_enabled BOOLEAN DEFAULT 0,
                max_products INTEGER DEFAULT 10,
                notification_preferences TEXT DEFAULT 'instant',
                scrapingbee_api_key TEXT
            )
        ''')

        # Products table - COMPLETE schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_email TEXT NOT NULL,
                product_url TEXT NOT NULL,
                product_title TEXT,
                current_rank TEXT,
                current_category TEXT,
                is_bestseller BOOLEAN DEFAULT 0,
                last_checked TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Rankings history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rankings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER,
                rank_number INTEGER,
                category TEXT,
                is_bestseller BOOLEAN,
                screenshot_data TEXT,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products (id)
            )
        ''')

        # Screenshots table for bestseller achievements
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bestseller_screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER,
                screenshot_data TEXT,
                rank_achieved TEXT,
                category TEXT,
                achieved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products (id)
            )
        ''')

        # Target categories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER,
                category_name TEXT NOT NULL,
                target_rank INTEGER DEFAULT 1,
                best_rank_achieved INTEGER,
                is_achieved BOOLEAN DEFAULT 0,
                date_achieved TIMESTAMP,
                screenshot_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products (id),
                FOREIGN KEY (screenshot_id) REFERENCES bestseller_screenshots (id)
            )
        ''')

        # Baseline screenshots table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline_screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER UNIQUE,
                screenshot_data TEXT,
                initial_rank TEXT,
                initial_category TEXT,
                captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products (id)
            )
        ''')

        # Login history for security monitoring
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                ip_address TEXT,
                user_agent TEXT,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Email verification tokens with expiry
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                token TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Sessions table for remember me functionality
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT UNIQUE,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Feedback table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_email TEXT,
                rating INTEGER,
                love TEXT,
                improve TEXT,
                bugs TEXT,
                would_pay TEXT,
                price_point TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        print("✅ All SQLite tables created with complete schema")

    def add_subscription_columns(self):
        """Add subscription fields if they don't exist"""
        conn = get_db()
        cursor = conn.cursor()

        try:
            if get_db_type() == 'postgresql':
                cursor.execute("""
                    ALTER TABLE users 
                    ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(20) DEFAULT 'free',
                    ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(20) DEFAULT 'inactive',
                    ADD COLUMN IF NOT EXISTS subscription_expires TIMESTAMP,
                    ADD COLUMN IF NOT EXISTS paddle_subscription_id VARCHAR(100),
                    ADD COLUMN IF NOT EXISTS paddle_customer_id VARCHAR(100),
                    ADD COLUMN IF NOT EXISTS max_products INTEGER DEFAULT 0
                """)
            else:
                # For SQLite, check if columns exist first
                cursor.execute("PRAGMA table_info(users)")
                existing_columns = [col[1] for col in cursor.fetchall()]

                if 'subscription_tier' not in existing_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN subscription_tier VARCHAR(20) DEFAULT 'free'")
                if 'subscription_status' not in existing_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN subscription_status VARCHAR(20) DEFAULT 'inactive'")
                # ... repeat for other columns

            conn.commit()
            print("✅ Subscription columns added/verified")
        except Exception as e:
            print(f"⚠️ Error adding subscription columns: {e}")
        finally:
            conn.close()

class User(UserMixin):
    """Enhanced User model with proper initialization"""
    def __init__(self, id, email, full_name=None, is_verified=False, is_active=True):
        self.id = id  # Make sure ID is set!
        self.email = email
        self.full_name = full_name
        self.is_verified = is_verified
        self.account_active = is_active

    def get_id(self):
        """Return the user ID as a string for Fla"""
        return str(self.id)

    def __repr__(self):
        return f'<User {self.email}>'

class APIRateLimiter:
    """Track and enforce per-user daily API usage limits"""
    DAILY_LIMIT_PER_USER = 3000

    @staticmethod
    def get_user_usage_today(user_id):
        """Get API calls made by a specific user today"""
        conn = get_db()
        cursor = conn.cursor()

        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

        try:
            if get_db_type() == 'postgresql':
                cursor.execute("""
                    SELECT COUNT(*) FROM api_usage 
                    WHERE user_id = %s AND called_at >= %s
                """, (user_id, today_start))
            else:
                cursor.execute("""
                    SELECT COUNT(*) FROM api_usage 
                    WHERE user_id = ? AND called_at >= ?
                """, (user_id, today_start))

            result = cursor.fetchone()
            # Handle different types of database return values
            if result is None:
                return 0
            elif isinstance(result, (list, tuple)) and len(result) > 0:
                return result[0] if result[0] is not None else 0
            elif isinstance(result, dict) and 'count' in result:
                return result['count']
            else:
                print(f"⚠️ Unexpected result format in get_user_usage_today: {result}")
                return 0
        finally:
            conn.close()

    @staticmethod
    def check_and_increment(user_id, endpoint='scrape'):
        """Check if user is under their daily limit and record usage"""
        conn = get_db()
        cursor = conn.cursor()

        try:
            current_usage = APIRateLimiter.get_user_usage_today(user_id)

            if current_usage >= APIRateLimiter.DAILY_LIMIT_PER_USER:
                remaining_hours = 24 - datetime.now().hour
                return False, f"You've reached your daily limit of {APIRateLimiter.DAILY_LIMIT_PER_USER} API calls. Resets in {remaining_hours} hours."

            # Record the API call for this user
            if get_db_type() == 'postgresql':
                cursor.execute(
                    "INSERT INTO api_usage (user_id, called_at, endpoint) VALUES (%s, %s, %s)",
                    (user_id, datetime.now(), endpoint)
                )
            else:
                cursor.execute(
                    "INSERT INTO api_usage (user_id, called_at, endpoint) VALUES (?, ?, ?)",
                    (user_id, datetime.now(), endpoint)
                )

            conn.commit()
            return True, None
        finally:
            conn.close()

# Create the api_usage table
def create_api_usage_table():
    """Create table to track API usage per user"""
    conn = get_db()
    cursor = conn.cursor()

    if get_db_type() == 'postgresql':
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_usage (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                called_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                endpoint TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        # Add index for faster queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_usage_user_date 
            ON api_usage(user_id, called_at)
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                called_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                endpoint TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_usage_user_date 
            ON api_usage(user_id, called_at)
        """)

    conn.commit()
    conn.close()

# Call during initialization
create_api_usage_table()

class EmailNotifier:
    """Email notifications using Resend"""
    def __init__(self):
        self.use_resend = os.environ.get('USE_RESEND', 'false').lower() == 'true'
        self.use_ses = os.environ.get('USE_SES', 'false').lower() == 'true'

        if self.use_resend:
            import resend
            resend.api_key = os.environ.get('RESEND_API_KEY')
            self.sender_email = 'noreply@screenshottracker.com'
        
        if self.use_ses:
            # Amazon SES setup
            self.ses_client = boto3.client(
                'ses',
                region_name=os.environ.get('AWS_REGION', 'us-east-1'),
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
            )
            self.sender_email = os.environ.get('SES_FROM_EMAIL', 'noreply@example.com')
            self.sender_name = os.environ.get('SENDER_NAME', 'Amazon Screenshot Tracker')
        else:
            # Fallback to SMTP (for development)
            self.smtp_server = os.environ.get('SMTP_SERVER')
            self.smtp_port = int(os.environ.get('SMTP_PORT', 587))
            self.username = os.environ.get('SMTP_USERNAME')
            self.password = os.environ.get('SMTP_PASSWORD')
            self.sender_email = os.environ.get('SENDER_EMAIL')
            self.sender_name = os.environ.get('SENDER_NAME', 'Amazon Screenshot Tracker')

    def is_configured(self):
        """Check if email is configured"""
        if self.use_ses:
            return bool(os.environ.get('AWS_ACCESS_KEY_ID'))
        else:
            return all([self.smtp_server, self.username, self.password])

    def _send_via_resend(self, recipient, subject, html_content, attachments=None):
        try:
            import resend
            resend.api_key = os.environ.get('RESEND_API_KEY')

            # Try their exact format from docs
            email = resend.Emails.send({
                "from": "Screenshot Tracker <noreply@screenshottracker.com>",
                "to": [recipient] if not isinstance(recipient, list) else recipient,
                "subject": subject,
                "html": html_content
            })

            print(f"✅ Resend response: {email}")
            return True

        except Exception as e:
            print(f"❌ Resend error: {str(e)}")
            return False

    def send_email(self, recipient, subject, html_content, attachments=None):
        if not self.is_configured():
            print("Email not configured")
            return False

        if self.use_resend:
            return self._send_via_resend(recipient, subject, html_content, attachments)
        elif self.use_ses:
            return self._send_via_ses(recipient, subject, html_content, attachments)
        else:
            return self._send_via_smtp(recipient, subject, html_content, attachments)

    def _send_via_ses(self, recipient, subject, html_content, attachments=None):
        """Send email using Amazon SES"""
        try:
            # For emails without attachments (most cases)
            if not attachments:
                response = self.ses_client.send_email(
                    Source=f'{self.sender_name} <{self.sender_email}>',
                    Destination={'ToAddresses': [recipient]},
                    Message={
                        'Subject': {'Data': subject},
                        'Body': {'Html': {'Data': html_content}}
                    }
                )
                print(f"Email sent via SES: {response['MessageId']}")
                return True

            else:
                # For achievement screenshots with attachments
                from email.mime.multipart import MIMEMultipart
                from email.mime.text import MIMEText
                from email.mime.application import MIMEApplication

                msg = MIMEMultipart()
                msg['Subject'] = subject
                msg['From'] = f'{self.sender_name} <{self.sender_email}>'
                msg['To'] = recipient

                # HTML body
                msg.attach(MIMEText(html_content, 'html'))

                # Add attachments
                for attachment in attachments:
                    msg.attach(attachment)

                # Send raw email
                response = self.ses_client.send_raw_email(
                    Source=self.sender_email,
                    Destinations=[recipient],
                    RawMessage={'Data': msg.as_string()}
                )
                print(f"Email with attachment sent via SES: {response['MessageId']}")
                return True

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']

            if error_code == 'MessageRejected':
                print(f"SES rejected message: {error_message}")
            elif error_code == 'MailFromDomainNotVerified':
                print(f"Domain not verified in SES: {error_message}")
            elif error_code == 'ConfigurationSetDoesNotExist':
                print(f"SES configuration issue: {error_message}")
            else:
                print(f"SES error {error_code}: {error_message}")

            return False

        except Exception as e:
            print(f"Failed to send email via SES: {e}")
            return False

    def _send_via_smtp(self, recipient, subject, html_content, attachments=None):
        """Original SMTP implementation for development"""
        # Your existing SMTP code here
        import socket
        #import smtplib
        #from email.mime.multipart import MIMEMultipart
        #from email.mime.text import MIMEText

        try:
            msg = MIMEMultipart('related')
            msg['Subject'] = subject
            msg['From'] = f'{self.sender_name} <{self.sender_email}>'
            msg['To'] = recipient
            msg.attach(MIMEText(html_content, 'html'))

            if attachments:
                for attachment in attachments:
                    msg.attach(attachment)

            if self.smtp_server is None:
                raise ValueError("SMTP_SERVER must be set in environment variables")
            # Proceed with establishing connection if server value is valid
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                server.starttls()
                if self.username is None or self.password is None:
                    raise ValueError("SMTP_USERNAME and SMTP_PASSWORD must be set in environment variables")
                server.login(self.username, self.password)
                server.send_message(msg)

            print(f"Email sent via SMTP to {recipient}")
            return True

        except Exception as e:
            print(f"SMTP error: {e}")
            return False

    def send_verification_email_async(self, email, token):
        """Send verification email in background thread"""
        import threading

        def _send():
            self.send_verification_email(email, token)

        thread = threading.Thread(target=_send, daemon=True)
        thread.start()
        return True  # Return immediately

    def send_verification_email(self, email, token):
        """Send email verification link"""
        try:
            base_url = request.host_url.rstrip('/')
        except RuntimeError:
            base_url = os.environ.get('APP_URL', 'http://localhost:5000')

        verification_link = f"{base_url}/auth/verify_email?token={token}"

        # Get the reusable footer
        footer = self.get_email_footer()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .container {{
                    background-color: #f8f9fa;
                    border-radius: 10px;
                    padding: 30px;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    color: #232f3e;
                    margin-bottom: 10px;
                }}
                .button {{
                    display: inline-block;
                    padding: 14px 30px;
                    background-color: #ff9900;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .warning {{
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 10px;
                    border-radius: 5px;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🏆 Welcome to Amazon Screenshot Tracker!</h1>
                    <p>You're just one click away from tracking your Amazon success</p>
                </div>

                <p>Hi there!</p>

                <p>Thanks for joining! Please verify your email address to start monitoring your Amazon products and capturing those valuable ranking screenshots.</p>

                <div style="text-align: center;">
                    <a href="{verification_link}" class="button">Verify Email Address</a>
                </div>

                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background-color: #f5f5f5; padding: 10px; border-radius: 5px;">
                    {verification_link}
                </p>

                <div class="warning">
                    <strong>⏰ This link expires in 24 hours</strong><br>
                    If you didn't create an account, you can safely ignore this email.
                </div>

                {footer}
            </div>
        </body>
        </html>
        """

        return self.send_email(
            email,
            "Verify Your Email - Amazon Screenshot Tracker",
            html_content
        )

    def get_email_footer(self):
        """Reusable professional email footer for all emails"""
        return """
        <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #eee;">
            <div style="text-align: center; color: #666; font-size: 14px;">
                <p><strong>Amazon Screenshot Tracker</strong></p>
                <p style="font-size: 12px; margin: 10px 0;">
                    This is an automated notification. Please do not reply to this email.
                </p>
                <p style="font-size: 12px;">
                    Questions or feedback? Email us at: 
                    <a href="mailto:support@amazonscreenshottracker.com" style="color: #ff9900;">
                        support@amazonscreenshottracker.com
                    </a>
                </p>
                <div style="margin-top: 15px; font-size: 11px; color: #999;">
                    <p>
                        <a href="#" style="color: #999;">Unsubscribe</a> | 
                        <a href="#" style="color: #999;">Email Preferences</a> | 
                        <a href="#" style="color: #999;">Privacy Policy</a>
                    </p>
                    <p style="margin-top: 10px;">
                        © 2025 Amazon Screenshot Tracker. Not affiliated with Amazon.com, Inc.<br>
                        Amazon is a trademark of Amazon.com, Inc.
                    </p>
                </div>
            </div>
        </div>
        """

    def send_password_reset_email(self, email, token):
        """Send password reset email"""
        try:
            base_url = request.host_url.rstrip('/')
        except RuntimeError:
            base_url = os.environ.get('APP_URL', 'http://localhost:5000')

        reset_link = f"{base_url}/auth/reset_password?token={token}"

        # Get the reusable footer
        footer = self.get_email_footer()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .container {{
                    background-color: #f8f9fa;
                    border-radius: 10px;
                    padding: 30px;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    color: #232f3e;
                }}
                .button {{
                    display: inline-block;
                    padding: 14px 30px;
                    background-color: #ff9900;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .warning {{
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 10px;
                    border-radius: 5px;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Password Reset Request</h1>
                </div>

                <p>Hi there!</p>

                <p>We received a request to reset your password for your Amazon Screenshot Tracker account.</p>

                <div style="text-align: center;">
                    <a href="{reset_link}" class="button">Reset Password</a>
                </div>

                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background-color: #f5f5f5; padding: 10px; border-radius: 5px;">
                    {reset_link}
                </p>

                <div class="warning">
                    <strong>⏰ This link expires in 1 hour</strong><br>
                    If you didn't request a password reset, you can safely ignore this email. Your password won't be changed.
                </div>

                {footer}
            </div>
        </body>
        </html>
        """

        return self.send_email(
            email,
            "Password Reset - Amazon Screenshot Tracker",
            html_content
        )

    def send_bestseller_notification(self, recipient_email, product_info, screenshot_data, achievement_type='bestseller'):
        """Send email notification with bestseller screenshot attached"""

        # Get the reusable footer
        footer = self.get_email_footer()

        if achievement_type == 'bestseller':
            rank_text = f"#{product_info['rank']}" if product_info['rank'] else "Bestseller"
            category_text = f" in {product_info['category']}" if product_info['category'] else ""
            achievement_text = f"achieved {rank_text}{category_text}"
        else:
            achievement_text = f"reached your target rank in {achievement_type}"

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: #ff9900;
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    background-color: #f8f9fa;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }}
                .achievement-box {{
                    background-color: white;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .product-title {{
                    font-size: 18px;
                    font-weight: bold;
                    color: #232f3e;
                    margin-bottom: 10px;
                }}
                .rank-display {{
                    font-size: 36px;
                    font-weight: bold;
                    color: #ff9900;
                    margin: 10px 0;
                }}
                .screenshot-preview {{
                    margin: 20px 0;
                    text-align: center;
                }}
                .screenshot-preview img {{
                    max-width: 100%;
                    border: 2px solid #ddd;
                    border-radius: 8px;
                    max-height: 400px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🏆 Achievement Unlocked!</h1>
            </div>
            <div class="content">
                <p>Congratulations! Your product has {achievement_text}!</p>

                <div class="achievement-box">
                    <div class="product-title">{product_info['title']}</div>
                    <div class="rank-display">#{product_info['rank'] or '1'}</div>
                    <div>in {product_info['category'] or 'its category'}</div>
                    <div style="color: #666; margin-top: 10px;">
                        Achieved on: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
                    </div>
                </div>

                <div class="screenshot-preview">
                    <h3>Screenshot Evidence</h3>
                    <p>We've captured a screenshot of your achievement! The full-size image is attached to this email.</p>
                    <img src="cid:screenshot" alt="Achievement Screenshot">
                </div>

                <div style="margin-top: 30px; padding: 20px; background-color: #e8f4f8; border-radius: 8px;">
                    <h3 style="color: #232f3e; margin-top: 0;">🎯 Keep Going!</h3>
                    <p>Track more products and never miss another achievement:</p>
                    <div style="text-align: center; margin-top: 15px;">
                        <a href="{os.environ.get('APP_URL', '#')}/dashboard" 
                           style="display: inline-block; padding: 12px 30px; background-color: #ff9900; 
                                  color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
                            View Dashboard
                        </a>
                    </div>
                </div>

                {footer}
            </div>
        </body>
        </html>
        """

        attachments = []
        if screenshot_data:
            # Decode base64 screenshot data
            if screenshot_data.startswith('data:image'):
                screenshot_data = screenshot_data.split(',')[1]

            img_data = base64.b64decode(screenshot_data)

            # Create image attachment
            img = MIMEImage(img_data)
            img.add_header('Content-ID', '<screenshot>')
            img.add_header('Content-Disposition', 'attachment', 
                         filename=f'achievement_screenshot_{product_info["title"][:30]}.png')
            attachments.append(img)

        return self.send_email(
            recipient_email,
            f"🏆 Achievement: {product_info['title'][:50]}...",
            html_content,
            attachments
        )

class APIKeyEncryption:
    def __init__(self):
        # Generate a key from your secret
        if CRYPTOGRAPHY_AVAILABLE:
            from cryptography.fernet import Fernet  # Local import to satisfy type checker
            secret = app.config['SECRET_KEY'].encode()
            self.cipher = Fernet(base64.urlsafe_b64encode(secret[:32].ljust(32, b'0')))
        else:
            print("⚠️  API key encryption disabled (cryptography not available)")
            self.cipher = None

    def encrypt(self, api_key):
        """Encrypt API key before storing"""
        if not api_key:
            return None
        if not self.cipher:
            print("⚠️  Storing API key in plain text (encryption disabled)")
            return api_key  # Store in plain text if encryption not available
        return self.cipher.encrypt(api_key.encode()).decode()

    def decrypt(self, encrypted_key):
        """Decrypt API key for use"""
        if not encrypted_key:
            return None
        if not self.cipher:
            return encrypted_key  # Return as-is if encryption not available
        return self.cipher.decrypt(encrypted_key.encode()).decode()

class AmazonMonitor:
    def __init__(self, api_key=None, user_id=None):
        self.api_key = api_key or SCRAPINGBEE_API_KEY
        self.user_id = user_id  # Track which user is making the call

    @classmethod
    def for_user(cls, user_id):
        """Create monitor instance for a specific user"""
        if not SCRAPINGBEE_API_KEY:
            print("❌ No global ScrapingBee API key configured")
            return cls(None, user_id)

        print(f"✅ Using global API key for user {user_id}")
        return cls(SCRAPINGBEE_API_KEY, user_id)

    def scrape_amazon_page(self, url, need_screenshot=True):
        """Scrape Amazon page - optionally with screenshot

        Args:
            url: Amazon product URL
            need_screenshot: If False, saves 15 credits by skipping screenshot

        Returns:
            dict with success, error, html, and screenshot data
        """
        # Rate limiting check
        if self.user_id:
            can_call, error_msg = APIRateLimiter.check_and_increment(self.user_id)
            if not can_call:
                print(f"❌ Rate limit exceeded: {error_msg}")
                return {
                    'success': False, 
                    'error': error_msg,
                    'html': '',
                    'screenshot': None
                }

        if not self.api_key:
            print("❌ ScrapingBee API key not configured")
            return {'success': False, 'error': 'API key not configured', 'html': '', 'screenshot': None}

        # First, always get HTML
        html_params = {
            'api_key': self.api_key,
            'url': url,
            'premium_proxy': 'true',
            'country_code': 'us',
            'window_width': 1920,
            'window_height': 1080,
            'wait': 2000,  # Reduced from 3000
            'wait_for': '#productTitle'
        }

        try:
            print("📊 Fetching HTML content...")
            html_response = requests.get('https://app.scrapingbee.com/api/v1/', params=html_params, timeout=25)

            if html_response.status_code != 200:
                print(f"❌ Failed to get HTML: {html_response.status_code}")
                return {
                    'success': False,
                    'error': f'ScrapingBee HTML error: {html_response.status_code}',
                    'html': '',
                    'screenshot': None
                }

            html_content = html_response.text
            print(f"✅ Got HTML content ({len(html_content)} chars)")

            screenshot_data = None

            # If screenshot needed, make second call
            if need_screenshot:
                print("📸 Fetching screenshot...")
                screenshot_params = {
                    'api_key': self.api_key,
                    'url': url,
                    'premium_proxy': 'true',
                    'country_code': 'us',
                    'screenshot': 'true',
                    'screenshot_full_page': 'true',
                    'window_width': 1920,
                    'window_height': 1080,
                    'wait': 2000,  # Reduced from 3000
                    'block_ads': 'true',  # Add this - blocks ads which speeds up rendering
                    'block_resources': 'false'  # Keep resources for proper rendering
                }

                try:
                    screenshot_response = requests.get('https://app.scrapingbee.com/api/v1/', 
                                                      params=screenshot_params, timeout=25)

                    if screenshot_response.status_code == 200:
                        screenshot_data = screenshot_response.content
                        print(f"✅ Got screenshot ({len(screenshot_data)} bytes)")
                    else:
                        print(f"⚠️ Screenshot failed: {screenshot_response.status_code}")
                except requests.exceptions.Timeout:
                    print("⚠️ Screenshot timed out, continuing without it")
                except Exception as e:
                    print(f"⚠️ Screenshot error: {e}, continuing without it")

            return {
                'success': True,
                'error': None,
                'html': html_content,
                'screenshot': screenshot_data
            }

        except requests.exceptions.Timeout:
            print("❌ Request timed out")
            return {
                'success': False,
                'error': 'Request timed out',
                'html': '',
                'screenshot': None
            }
        except Exception as e:
            print(f"❌ Error during scraping: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'html': '',
                'screenshot': None
            }

    def extract_product_info(self, html):
        """Extract product ranking and bestseller info from Amazon HTML - FIXED"""
        if not html:
            print("⚠️ No HTML content to extract from")
            return {
                'title': 'Product Title Loading...',
                'rank': None,
                'category': '',
                'is_bestseller': False,
                'bestseller_categories': []
            }

        soup = BeautifulSoup(html, 'html.parser')

        product_info = {
            'title': '',
            'rank': None,
            'category': '',
            'is_bestseller': False,
            'bestseller_categories': []
        }

        try:
            print("🔍 Starting HTML parsing...")

            # Extract title - multiple methods with more selectors
            title_selectors = [
                ('span', {'id': 'productTitle'}),
                ('h1', {'id': 'title'}),
                ('h1', {'class': 'a-size-large'}),
                ('span', {'class': 'a-size-large product-title-word-break'}),
                ('h1', {'class': 'a-size-large a-spacing-none'}),
                ('span', {'class': 'a-size-large'}),
                ('h1', {'data-automation-id': 'title'}),
                ('span', {'class': 'product-title'}),
                ('h1', {}),  # Fallback to any h1
                ('title', {})  # HTML title tag
            ]

            print(f"🔍 Searching for title in HTML (length: {len(html)} chars)")
            
            for i, (tag, attrs) in enumerate(title_selectors):
                if attrs:
                    # Use specific approach to satisfy type checker
                    if 'id' in attrs:
                        title_element = soup.find(tag, id=attrs['id'])
                    elif 'class' in attrs:
                        title_element = soup.find(tag, class_=attrs['class'])
                    elif 'data-automation-id' in attrs:
                        title_element = soup.find(tag, **{'data-automation-id': attrs['data-automation-id']})
                    else:
                        title_element = soup.find(tag)
                    print(f"🔍 Selector {i+1}: Looking for <{tag}> with {attrs} - {'Found' if title_element else 'Not found'}")
                else:
                    title_element = soup.find(tag)
                    print(f"🔍 Selector {i+1}: Looking for <{tag}> - {'Found' if title_element else 'Not found'}")
                    
                if title_element:
                    title_text = ' '.join(title_element.stripped_strings)
                    if title_text and len(title_text) > 5:  # Ensure meaningful title
                        product_info['title'] = title_text
                        print(f"📋 Found title with selector {i+1}: {product_info['title'][:100]}...")
                        break

            if not product_info['title']:
                # Try meta tags as fallback
                meta_selectors = [
                    ('meta', {'property': 'og:title'}),
                    ('meta', {'name': 'title'}),
                    ('meta', {'property': 'twitter:title'})
                ]
                
                for tag, attrs in meta_selectors:
                    # Use specific approach for meta tags to avoid parameter conflicts
                    if 'property' in attrs:
                        meta_element = soup.find(tag, property=attrs['property'])
                    elif 'name' in attrs:
                        # Use attrs parameter for 'name' attribute to avoid conflict with BeautifulSoup's name parameter
                        meta_element = soup.find(tag, attrs={'name': attrs['name']})  # type: ignore
                    else:
                        meta_element = soup.find(tag)
                    if meta_element:
                        # Use safe attribute access for BeautifulSoup elements
                        try:
                            content = meta_element.get('content')  # type: ignore
                            if content and len(content) > 5:
                                product_info['title'] = content
                                print(f"📋 Found title in meta tag: {product_info['title'][:100]}...")
                                break
                        except (AttributeError, TypeError):
                            # Fallback for different BeautifulSoup element types
                            continue

            if not product_info['title']:
                # Final fallback - log some debugging info
                print("⚠️ Could not find product title with any selector")
                print(f"🔍 Page has {len(soup.find_all('span'))} span tags")
                print(f"🔍 Page has {len(soup.find_all('h1'))} h1 tags") 
                
                
                # Check if this looks like a bot detection or JavaScript page
                page_text_lower = soup.get_text().lower()
                if 'javascript' in page_text_lower and 'disabled' in page_text_lower:
                    print("🤖 Detected JavaScript disabled message - bot detection likely")
                elif 'robot' in page_text_lower or 'automation' in page_text_lower:
                    print("🤖 Detected robot/automation detection")
                elif len(soup.get_text().strip()) < 1000:
                    print("⚠️ Very little text content - likely redirect or error page")
                
                # Debug: Show first 500 chars of content
                content_preview = soup.get_text()[:500].replace('\n', ' ').strip()
                print(f"🔍 Content preview: {content_preview}")
                
                # Check for specific Amazon bot detection indicators
                if 'sorry' in page_text_lower and 'automated' in page_text_lower:
                    print("🚫 Amazon bot detection: 'Sorry, automated requests detected'")
                elif 'captcha' in page_text_lower:
                    print("🚫 Amazon served a CAPTCHA page")
                elif 'blocked' in page_text_lower:
                    print("🚫 Request appears to be blocked by Amazon")
                
                product_info['title'] = 'Unknown Product'

            # Check for bestseller badges
            badge_patterns = [
                'best seller',
                'best-seller', 
                'bestseller',
                '#1 best seller',
                'amazon\'s choice'
            ]

            def has_badge_class(x):
                """Check if class contains 'badge'"""
                if x is None:
                    return False
                if isinstance(x, list):
                    return any('badge' in str(c).lower() for c in x)
                return 'badge' in str(x).lower()

            for element in soup.find_all(['span', 'div', 'a'], class_=has_badge_class):
                text = element.get_text().strip().lower()
                for pattern in badge_patterns:
                    if pattern in text:
                        product_info['is_bestseller'] = True
                        print(f"🏆 Found bestseller badge: {text}")
                        break

            # Extract ranking - search entire page
            print("🔍 Searching for ranking information...")

            # Look for "Best Sellers Rank"
            page_text = soup.get_text()

            # Multiple patterns for rank extraction
            rank_patterns = [
                r'Best Sellers Rank[:\s]*#?([\d,]+)\s+in\s+([^(\n]+)',
                r'Amazon Best Sellers Rank[:\s]*#?([\d,]+)\s+in\s+([^(\n]+)',
                r'#([\d,]+)\s+in\s+([^(\n#]+)'
            ]

            for pattern in rank_patterns:
                matches = re.findall(pattern, page_text, re.IGNORECASE)
                if matches:
                    for match in matches:
                        rank_num = match[0].replace(',', '').strip()
                        category = match[1].strip()

                        if rank_num.isdigit() and len(category) > 2:
                            product_info['rank'] = rank_num
                            product_info['category'] = category.split('(')[0].strip()
                            print(f"📈 Found rank: #{rank_num} in {product_info['category']}")

                            if rank_num == '1':
                                product_info['is_bestseller'] = True
                                print("🏆 Product is #1 - marking as bestseller!")
                            break

                    if product_info['rank']:
                        break

            # If no rank found, try more specific selectors
            if not product_info['rank']:
                rank_elements = soup.find_all(text=re.compile(r'#\d+\s+in', re.I))
                for elem in rank_elements[:5]:
                    if elem:
                        # elem is already a string (NavigableString), not a Tag
                        text = str(elem).strip()
                        if text:
                            match = re.search(r'#([\d,]+)\s+in\s+([^(\n]+)', text)
                            if match:
                                product_info['rank'] = match.group(1).replace(',', '')
                                product_info['category'] = match.group(2).strip()
                                print(f"📈 Found rank in element: #{product_info['rank']} in {product_info['category']}")
                                break

        except Exception as e:
            print(f"❌ Error extracting product info: {e}")
            import traceback
            traceback.print_exc()

        print(f"📊 Final product info: Title='{product_info['title'][:50]}...', Rank={product_info['rank']}, Category={product_info['category']}")
        return product_info

    def extract_category_from_text(self, text):
        """Extract category from text containing bestseller information"""
        try:
            if text:
                # Look for "in [Category]" pattern
                category_match = re.search(r'in (.+?)(?:\s|$)', text)
                if category_match:
                    return category_match.group(1).strip()

        except Exception as e:
            print(f"Error extracting category from text: {e}")
        return None

    def check_category_achievements(self, product_id, product_info, current_rank, current_category):
        """Check if product has achieved target category rankings"""
        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        # Get all target categories for this product
        cursor.execute('''
            SELECT id, category_name, target_rank, best_rank_achieved
            FROM target_categories 
            WHERE product_id = ? AND is_achieved = 0
        ''', (product_id,))

        target_categories = cursor.fetchall()
        achievements = []

        for target_id, target_category, target_rank, best_rank in target_categories:
            # Check if current category matches (case-insensitive partial match)
            if target_category.lower() in current_category.lower():
                current_rank_num = int(current_rank) if current_rank else None

                if current_rank_num:
                    # Update best rank if this is better
                    if not best_rank or current_rank_num < best_rank:
                        cursor.execute('''
                            UPDATE target_categories 
                            SET best_rank_achieved = ? 
                            WHERE id = ?
                        ''', (current_rank_num, target_id))

                    # Check if target achieved
                    if current_rank_num <= target_rank:
                        cursor.execute('''
                            UPDATE target_categories 
                            SET is_achieved = 1, date_achieved = ? 
                            WHERE id = ?
                        ''', (datetime.now(), target_id))

                        achievements.append({
                            'category': target_category,
                            'rank': current_rank_num,
                            'target_rank': target_rank
                        })

                        print(f"🎯 Target achieved! #{current_rank_num} in {target_category}")

        conn.commit()
        conn.close()

        return achievements

# ============= INITIALIZE COMPONENTS =============
db_manager = DatabaseManager()
db_manager.add_subscription_columns()
db_manager.add_achievement_tracking_columns()
email_notifier = EmailNotifier()
api_encryption = APIKeyEncryption()
monitor = AmazonMonitor(SCRAPINGBEE_API_KEY)

# ============= ERROR HANDLERS =============
@app.errorhandler(404)
def bad_request(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('The form submission has expired. Please try again.', 'error')
    return redirect(request.referrer or url_for('index'))

@app.errorhandler(429)
def rate_limit_handler(e):
    """Handle rate limit exceeded errors"""
    flash('Rate limit exceeded. Please wait a moment and try again.', 'warning')
    return redirect(request.referrer or url_for('dashboard'))

# ============= SECURITY HEADERS =============
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ============= ROUTES =============

def initialize_app():
    """Initialize the application and start scheduler"""
    print("🚀 Initializing Amazon Bestseller Monitor...")


    # Start scheduler
    if ensure_scheduler_running():
        print("✅ Scheduler started successfully during app initialization")
    else:
        print("⚠️ Scheduler will start on first request")

    return app

# Initialize scheduler when module loads (for gunicorn)
# This should work even if before_first_request doesn't exist
print("🔧 Checking Flask version and initializing scheduler...")

def init_scheduler_background():
    """Initialize scheduler in background without blocking"""
    global scheduler_initialized, scheduler_thread, scheduler_running

    # Wait a bit for app to fully start
    time.sleep(10)

    if scheduler_initialized:
        return

    if os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true':
        try:
            print("📅 Starting scheduler...")
            scheduler_thread = threading.Thread(
                target=run_scheduler,
                daemon=True,
                name="PerProductScheduler"
            )
            scheduler_thread.start()
            scheduler_initialized = True
            scheduler_running = True
            print("✅ Scheduler started successfully")
        except Exception as e:
            print(f"⚠️ Scheduler failed: {e}")
    else:
        print("⚠️ Scheduler is disabled")


def get_insert_id(cursor, conn):
    """Get last insert ID for both databases"""
    database_url = os.environ.get('DATABASE_URL')

    if database_url:
        # PostgreSQL: Use RETURNING
        # This function should be called differently for PostgreSQL
        return None  # Handle with RETURNING clause
    else:
        # SQLite
        return cursor.lastrowid

def execute_with_returning(cursor, query, params=None):
    """Execute INSERT and return ID for PostgreSQL compatibility"""
    database_url = os.environ.get('DATABASE_URL')

    if database_url:
        # PostgreSQL: Add RETURNING id
        if query.strip().upper().startswith('INSERT') and 'RETURNING' not in query.upper():
            query += ' RETURNING id'

        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        # Get the returned ID
        result = cursor.fetchone()
        return result['id'] if result else None
    else:
        # SQLite: Regular insert
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor.lastrowid

if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY must be set in environment variables!")

# CSRF Protection
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
print(f"CSRF Enabled: {app.config.get('WTF_CSRF_ENABLED', 'Not Set')}")
print(f"Secret Key Length: {len(app.config['SECRET_KEY'])}")

csp = {
    'default-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com',  # For any CDN resources
        'https://app.scrapingbee.com',  # For ScrapingBee
    ],
    'img-src': [
        '\'self\'',
        'data:',
        'https:',
        'blob:',
    ],
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'',  # Remove in production if possible
        'https://cdnjs.cloudflare.com',
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'',  # For inline styles
        'https://cdnjs.cloudflare.com',
    ],
    'font-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com',
    ],
}

@app.route('/admin/test_email_config')
@login_required
def test_email_config():
    """Test and diagnose email configuration"""
    # Security check
    ADMIN_EMAILS = ['amazonscreenshottracker@gmail.com']
    if current_user.email not in ADMIN_EMAILS:
        return "Unauthorized", 403

    diagnostics = []

    # Check environment variables
    diagnostics.append(f"SMTP_SERVER: {SMTP_SERVER or 'NOT SET'}")
    diagnostics.append(f"SMTP_PORT: {SMTP_PORT or 'NOT SET'}")
    diagnostics.append(f"SMTP_USERNAME: {'SET' if SMTP_USERNAME else 'NOT SET'}")
    diagnostics.append(f"SMTP_PASSWORD: {'SET' if SMTP_PASSWORD else 'NOT SET'}")
    diagnostics.append(f"SENDER_EMAIL: {SENDER_EMAIL or 'NOT SET'}")
    diagnostics.append(f"Email configured: {email_notifier.is_configured()}")

    # Try to send a test email
    if email_notifier.is_configured():
        try:
            import smtplib
            import socket

            # Test connection
            diagnostics.append("\nTesting SMTP connection...")

            socket.setdefaulttimeout(10)
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
            server.starttls()
            if SMTP_USERNAME is None or SMTP_PASSWORD is None:
                raise ValueError("SMTP_USERNAME and SMTP_PASSWORD must be set in environment variables")
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.quit()

            diagnostics.append("✅ SMTP connection successful!")

            # Try sending test email
            test_html = """
            <html>
                <body>
                    <h2>Test Email</h2>
                    <p>This is a test email from your Amazon Screenshot Tracker.</p>
                    <p>If you received this, your email configuration is working!</p>
                </body>
            </html>
            """

            result = email_notifier.send_email(
                current_user.email,
                "Test Email - Amazon Screenshot Tracker",
                test_html
            )

            if result:
                diagnostics.append(f"✅ Test email sent to {current_user.email}")
            else:
                diagnostics.append("❌ Failed to send test email")

        except Exception as e:
            diagnostics.append(f"❌ Error: {str(e)}")
            import traceback
            diagnostics.append(f"Traceback: {traceback.format_exc()}")
    else:
        diagnostics.append("❌ Email system not configured")

    return "<pre>" + "\n".join(diagnostics) + "</pre>"

@app.route('/admin/manual_verify', methods=['GET', 'POST'])
@login_required
def manual_verify():
    """Manual verification page for admin"""
    ADMIN_EMAILS = ['amazonscreenshottracker@gmail.com']
    if current_user.email not in ADMIN_EMAILS:
        return "Unauthorized", 403

    if request.method == 'POST':
        email = request.form.get('email')

        conn = get_db()
        cursor = conn.cursor()

        try:
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    UPDATE users SET is_verified = true 
                    WHERE LOWER(email) = LOWER(%s)
                ''', (email,))
            else:
                cursor.execute('''
                    UPDATE users SET is_verified = 1 
                    WHERE LOWER(email) = LOWER(?)
                ''', (email,))

            if cursor.rowcount > 0:
                conn.commit()
                flash(f'User {email} verified successfully!', 'success')
            else:
                flash(f'User {email} not found', 'error')

            conn.close()
        except Exception as e:
            conn.close()
            flash(f'Error: {str(e)}', 'error')

    # Get list of unverified users
    conn = get_db()
    cursor = conn.cursor()

    if get_db_type() == 'postgresql':
        cursor.execute('''
            SELECT email, created_at 
            FROM users 
            WHERE is_verified = false 
            ORDER BY created_at DESC
        ''')
    else:
        cursor.execute('''
            SELECT email, created_at 
            FROM users 
            WHERE is_verified = 0 
            ORDER BY created_at DESC
        ''')

    unverified_users = cursor.fetchall()
    conn.close()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Manual User Verification</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .user-list { background: #f5f5f5; padding: 20px; border-radius: 8px; }
            .user-item { background: white; padding: 10px; margin: 10px 0; border-radius: 5px; }
            .btn { background: #ff9900; color: white; padding: 8px 16px; border: none; border-radius: 5px; cursor: pointer; }
            .btn:hover { background: #e88b00; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Manual User Verification</h1>
            <p>Admin tool to manually verify users when email system is not working.</p>

            <h2>Verify by Email</h2>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input type="email" name="email" placeholder="user@email.com" required>
                <button type="submit" class="btn">Verify User</button>
            </form>

            <h2>Unverified Users</h2>
            <div class="user-list">
    """

    if unverified_users:
        for user in unverified_users:
            if isinstance(user, dict):
                email = user['email']
                created = user['created_at']
            else:
                email = user[0]
                created = user[1]

            html += f"""
                <div class="user-item">
                    <strong>{email}</strong> - Created: {created}
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="email" value="{email}">
                        <button type="submit" class="btn">Verify</button>
                    </form>
                </div>
            """
    else:
        html += "<p>No unverified users found.</p>"

    html += """
            </div>

            <h2>Quick Actions</h2>
            <p><a href="/admin/auto_verify_all" class="btn" onclick="return confirm('Verify ALL unverified users?')">Verify All Users</a></p>
            <p><a href="/admin/test_email_config" class="btn">Test Email Configuration</a></p>
        </div>
    </body>
    </html>
    """

    return render_template_string(html)

# Add this temporary admin route to fix your account:
@app.route('/admin/fix_subscription/<email>')
@login_required
def fix_subscription(email):

    conn = get_db()
    cursor = conn.cursor()

    # Manually activate the subscription
    if get_db_type() == 'postgresql':
        cursor.execute("""
            UPDATE users 
            SET subscription_status = 'active',
                subscription_tier = 'author',  # or 'publisher'
                max_products = 2,  # or 5 for publisher
                is_verified = true,
                subscription_expires = %s
            WHERE email = %s
        """, (datetime.now() + timedelta(days=30), email))

    conn.commit()
    conn.close()

    return f"Fixed subscription for {email}"

@app.route('/scheduler_health')
def scheduler_health():
    """Separate endpoint to check scheduler health"""
    global scheduler_thread

    scheduler_enabled = os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true'

    if not scheduler_enabled:
        return jsonify({
            'status': 'disabled',
            'message': 'Scheduler is disabled by configuration',
            'healthy': True
        })

    if scheduler_thread and scheduler_thread.is_alive():
        return jsonify({
            'status': 'running',
            'thread_alive': True,
            'healthy': True
        })
    else:
        return jsonify({
            'status': 'stopped',
            'thread_alive': False,
            'healthy': False,
            'message': 'Scheduler should be running but thread is dead'
        }), 503

@app.route('/scheduler_control')
@login_required
def scheduler_control():
    """Control panel for the scheduler"""
    if current_user.email != 'josh.matern@gmail.com':
        return "Unauthorized", 403

    global scheduler_thread
    import schedule

    scheduler_enabled = os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true'
    thread_alive = scheduler_thread and scheduler_thread.is_alive() if scheduler_thread else False
    job_count = len(schedule.jobs) if schedule else 0

    # Get next run time
    next_run = None
    if schedule.jobs:
        try:
            next_run = schedule.jobs[0].next_run
        except Exception as e:
            pass

    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; }}
            .status-box {{ 
                padding: 20px; 
                border-radius: 8px; 
                margin: 20px 0;
            }}
            .enabled {{ background: #d4edda; }}
            .disabled {{ background: #f8d7da; }}
            .warning {{ background: #fff3cd; }}
            .button {{
                padding: 10px 20px;
                margin: 10px;
                border-radius: 5px;
                text-decoration: none;
                display: inline-block;
                font-weight: bold;
            }}
            .start {{ background: #28a745; color: white; }}
            .stop {{ background: #dc3545; color: white; }}
            .info {{ background: #17a2b8; color: white; }}
        </style>
    </head>
    <body>
        <h1>⚙️ Scheduler Control Panel</h1>

        <div class="status-box {'enabled' if scheduler_enabled else 'disabled'}">
            <h2>Configuration</h2>
            <p><strong>ENABLE_SCHEDULER:</strong> {os.environ.get('ENABLE_SCHEDULER', 'false')}</p>
            <p><strong>Setting:</strong> {'ENABLED' if scheduler_enabled else 'DISABLED'}</p>
        </div>

        <div class="status-box {'enabled' if thread_alive else 'warning'}">
            <h2>Runtime Status</h2>
            <p><strong>Thread Alive:</strong> {'✅ Yes' if thread_alive else '❌ No'}</p>
            <p><strong>Scheduled Jobs:</strong> {job_count}</p>
            <p><strong>Next Run:</strong> {next_run or 'Not scheduled'}</p>
        </div>

        <div class="status-box warning">
            <h2>⚠️ Important Notes</h2>
            <ul>
                <li>To permanently enable/disable, change ENABLE_SCHEDULER in Railway environment variables</li>
                <li>Manual start/stop here is temporary until next deployment</li>
                <li>Health checks will pass even if scheduler is disabled</li>
            </ul>
        </div>

        <h2>Actions</h2>
        <a href="/start_scheduler" class="button start">▶️ Start Scheduler</a>
        <a href="/stop_scheduler" class="button stop">⏹️ Stop Scheduler</a>
        <a href="/clear_scheduled_jobs" class="button info">🗑️ Clear Jobs</a>

        <br><br>
        <a href="/scheduler_status" class="button info">📊 Scheduler Status</a>
        <a href="/credit_leak_detector" class="button info">🔍 Leak Detector</a>
        <a href="/dashboard" class="button info">🏠 Dashboard</a>
    </body>
    </html>
    """

    return html

@app.route('/start_scheduler')
@login_required
def start_scheduler():
    """Manually start the scheduler - FIXED"""
    if current_user.email != 'josh.matern@gmail.com':
        return "Unauthorized", 403

    global scheduler_thread

    if scheduler_thread and scheduler_thread.is_alive():
        flash('Scheduler is already running', 'info')
        return redirect(url_for('scheduler_control'))

    try:
        # Start new thread with CORRECT function name
        scheduler_thread = threading.Thread(
            target=run_scheduler,
            daemon=True, 
            name="SchedulerThread"
        )
        scheduler_thread.start()

        time.sleep(1)

        if scheduler_thread.is_alive():
            flash('✅ Scheduler started successfully', 'success')
        else:
            flash('❌ Scheduler failed to start', 'error')

    except Exception as e:
        flash(f'Error starting scheduler: {str(e)}', 'error')

    return redirect(url_for('scheduler_control'))


@app.route('/stop_scheduler')
@login_required
def stop_scheduler():
    """Stop the scheduler"""
    if current_user.email != 'josh.matern@gmail.com':
        return "Unauthorized", 403

    import schedule

    try:
        # Clear all jobs
        schedule.clear()

        # Set environment variable to stop the thread
        os.environ['ENABLE_SCHEDULER'] = 'false'

        flash('✅ Scheduler stopped. Thread will exit on next cycle (within 5 minutes)', 'success')

    except Exception as e:
        flash(f'Error stopping scheduler: {str(e)}', 'error')

    return redirect(url_for('scheduler_control'))


@app.route('/clear_scheduled_jobs')
@login_required
def clear_scheduled_jobs():
    """Clear all scheduled jobs"""
    if current_user.email != 'josh.matern@gmail.com':
        return "Unauthorized", 403

    import schedule

    try:
        job_count = len(schedule.jobs)
        schedule.clear()
        flash(f'✅ Cleared {job_count} scheduled jobs', 'success')
    except Exception as e:
        flash(f'Error clearing jobs: {str(e)}', 'error')

    return redirect(url_for('scheduler_control'))

@app.route('/scheduler_status')
def scheduler_status():
    """Public endpoint to check scheduler status and restart if needed"""
    global scheduler_thread, scheduler_running

    scheduler_enabled = os.environ.get('ENABLE_SCHEDULER', 'true').lower() == 'true'

    if not scheduler_enabled:
        return jsonify({
            'status': 'disabled',
            'message': 'Scheduler is disabled by configuration',
            'healthy': True
        })

    # Check if thread exists and is alive
    thread_exists = scheduler_thread is not None
    thread_alive = scheduler_thread.is_alive() if scheduler_thread else False

    if thread_alive:
        return jsonify({
            'status': 'running',
            'thread_alive': True,
            'healthy': True,
            'message': 'Scheduler is running normally'
        })
    else:
        # Try to restart it
        print("⚠️ Scheduler not running, attempting to restart...")

        if ensure_scheduler_running():
            return jsonify({
                'status': 'restarted',
                'thread_alive': True,
                'healthy': True,
                'message': 'Scheduler was down but has been restarted'
            })
        else:
            return jsonify({
                'status': 'failed',
                'thread_alive': False,
                'healthy': False,
                'message': 'Scheduler is down and could not be restarted'
            }), 503

# Also add a manual check to ensure scheduler is running
@app.route('/ensure_scheduler')
@login_required
def ensure_scheduler_endpoint():
    """Manually ensure scheduler is running - admin only"""
    if current_user.email not in ['josh.matern@gmail.com', 'amazonscreenshottracker@gmail.com']:
        return "Unauthorized", 403

    global scheduler_thread, scheduler_running

    html = "<h2>Scheduler Check</h2>"

    # Check current status
    if scheduler_thread and scheduler_thread.is_alive():
        html += "<p style='color: green;'>✅ Scheduler is already running!</p>"
    else:
        html += "<p style='color: red;'>❌ Scheduler was not running. Starting it now...</p>"

        if ensure_scheduler_running():
            html += "<p style='color: green;'>✅ Scheduler started successfully!</p>"
        else:
            html += "<p style='color: red;'>❌ Failed to start scheduler</p>"

    html += f"""
    <br>
    <p><strong>Thread object exists:</strong> {scheduler_thread is not None}</p>
    <p><strong>Thread alive:</strong> {scheduler_thread.is_alive() if scheduler_thread else False}</p>
    <p><strong>Scheduler running flag:</strong> {scheduler_running}</p>
    <p><strong>ENABLE_SCHEDULER:</strong> {os.environ.get('ENABLE_SCHEDULER', 'Not set')}</p>
    <br>
    <a href="/credit_leak_detector">Check Leak Detector</a> | 
    <a href="/dashboard">Dashboard</a>
    """

    return html

@app.route('/api/my_usage')
@login_required
def my_usage_stats():
    """Check current user's API usage"""
    usage_today = APIRateLimiter.get_user_usage_today(current_user.id)
    remaining = APIRateLimiter.DAILY_LIMIT_PER_USER - usage_today

    return jsonify({
        'used_today': usage_today,
        'daily_limit': APIRateLimiter.DAILY_LIMIT_PER_USER,
        'remaining': remaining,
        'percentage_used': round((usage_today / APIRateLimiter.DAILY_LIMIT_PER_USER) * 100, 1)
    })

@app.route('/csrf-test')
def csrf_test():
    return """
    <form method="POST" action="/csrf-test-post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button type="submit">Test CSRF</button>
    </form>
    """

@app.route('/csrf-test-post', methods=['POST'])
def csrf_test_post():
    return "CSRF token validated successfully!"

# Print email configuration status
if email_notifier.is_configured():
    print("✅ Email notifications configured")
else:
    print("⚠️ Email notifications not configured - emails will not be sent")
    print("To enable emails, set these environment variables:")
    print("  - SMTP_SERVER")
    print("  - SMTP_USERNAME") 
    print("  - SMTP_PASSWORD")


@login_manager.user_loader
def load_user(user_id):
    """Load user for Fla -sk-Login FIXED"""
    print(f"🔍 LOAD_USER: Loading user with ID {user_id}")
    
    conn = get_db()
    cursor = conn.cursor()

    try:
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT id, email, full_name, is_verified, is_active 
                FROM users WHERE id = %s
            ''', (int(user_id),))  # Ensure ID is integer
        else:
            cursor.execute('''
                SELECT id, email, full_name, is_verified, is_active 
                FROM users WHERE id = ?
            ''', (int(user_id),))

        user_data = cursor.fetchone()

        if user_data:
            # Handle both dict and tuple responses
            if isinstance(user_data, dict):
                user = User(
                    id=user_data['id'],
                    email=user_data['email'],
                    full_name=user_data['full_name'],
                    is_verified=bool(user_data['is_verified']),
                    is_active=bool(user_data['is_active'])
                )
            else:
                user = User(
                    id=user_data[0],
                    email=user_data[1],
                    full_name=user_data[2],
                    is_verified=bool(user_data[3]),
                    is_active=bool(user_data[4])
                )
            
            print(f"✅ LOAD_USER: Loaded user {user.email} (ID: {user.id})")
            return user
        else:
            print(f"❌ LOAD_USER: No user found with ID {user_id}")
            return None
            
    except Exception as e:
        print(f"❌ LOAD_USER: Error loading user: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        conn.close()

# Update the login route to ensure proper user creation
def create_user_session(user_data, email):
    """Helper function to create user object from database data"""
    if isinstance(user_data, dict):
        user = User(
            id=user_data['id'],
            email=user_data['email'] or email,
            full_name=user_data.get('full_name'),
           is_verified=bool(user_data.get('is_verified', False)),
            is_active=bool(user_data.get('is_active', True))
        )
    else:
        # Assuming tuple order: id, password_hash, is_verified, is_active, full_name, ...
        user = User(
            id=user_data[0],
            email=email,  # Use the email from login form
            full_name=user_data[4] if len(user_data) > 4 else None,
            is_verified=bool(user_data[2]) if len(user_data) > 2 else False,
            is_active=bool(user_data[3]) if len(user_data) > 3 else True
        )

    print(f"✅ CREATE_USER_SESSION: Created user object - ID: {user.id}, Email: {user.email}")
    return user


def validate_password(password):
    """Validate password meets security requirements"""
    errors = [] 

    if len(password) < PASSWORD_REQUIREMENTS['min_length']:
        errors.append(f"Password must be at least {PASSWORD_REQUIREMENTS['min_length']} characters")

    if PASSWORD_REQUIREMENTS['require_uppercase'] and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")

    if PASSWORD_REQUIREMENTS['require_lowercase'] and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")

    if PASSWORD_REQUIREMENTS['require_digit'] and not re.search(r'\d', password):
        errors.append("Password must contain at least one number")

    if PASSWORD_REQUIREMENTS['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")

    return errors

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def rate_limit(max_attempts=5, window=300):  # 5 attempts per 5 minutes
    """Decorator for rate limiting login attempts"""
    def decorator(f):
        attempts = {}

        @wraps(f)
        def wrapper(*args, **kwargs):
            identifier = request.remote_addr  # Use IP for rate limiting
            now = datetime.now()

            # Clean old attempts
            attempts_copy = attempts.copy()
            for key, value in attempts_copy.items():
                if (now - value['first_attempt']).seconds > window:
                    del attempts[key]

            # Check rate limit
            if identifier in attempts:
                if attempts[identifier]['count'] >= max_attempts:
                    time_left = window - (now - attempts[identifier]['first_attempt']).seconds
                    flash(f'Too many attempts. Please try again in {time_left} seconds.', 'error')
                    return redirect(url_for('auth.login'))
                attempts[identifier]['count'] += 1
            else:
                attempts[identifier] = {'count': 1, 'first_attempt': now}

            return f(*args, **kwargs)
        return wrapper
    return decorator

# Enhanced database schema
def create_enhanced_user_tables():
    """Create user tables with additional security features"""
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Enhanced users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            is_verified BOOLEAN DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            verification_token TEXT,
            verification_token_expiry TIMESTAMP,
            reset_token TEXT,
            reset_token_expiry TIMESTAMP,
            failed_login_attempts INTEGER DEFAULT 0,
            last_failed_login TIMESTAMP,
            account_locked_until TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            two_factor_secret TEXT,
            two_factor_enabled BOOLEAN DEFAULT 0,
            max_products INTEGER DEFAULT 10,
            notification_preferences TEXT DEFAULT 'instant'
        )
    ''')

    # Login history for security monitoring
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Email verification tokens with expiry
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

@auth.route('/setup-account', methods=['GET', 'POST'])
def setup_account():


    if request.method == 'POST':
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        token = request.form.get('token')

        # Validate password exists
        if not password:
            flash('Password is required', 'error')
            return render_template('setup_account.html', email=email, token=token)

        conn = get_db()
        cursor = conn.cursor()

        # Verify token and email match
        if get_db_type() == 'postgresql':
            cursor.execute("""
                SELECT id FROM users 
                WHERE email = %s AND setup_token = %s 
            """, (email, token))
        else:
            cursor.execute("""
                SELECT id FROM users 
                WHERE email = ? AND setup_token = ? 
            """, (email, token))

        user = cursor.fetchone()
        if not user:
            flash('Invalid or expired setup link', 'error')
            conn.close()
            return redirect(url_for('auth.login'))

        # Now password is guaranteed to be a string
        password_hash = generate_password_hash(password)

        if get_db_type() == 'postgresql':
            cursor.execute("""
                UPDATE users 
                SET password_hash = %s, full_name = %s, 
                    is_verified = true, setup_token = NULL
                WHERE id = %s
            """, (password_hash, full_name or '', user[0]))
        else:
            cursor.execute("""
                UPDATE users 
                SET password_hash = ?, full_name = ?, 
                    is_verified = 1, setup_token = NULL
                WHERE id = ?
            """, (password_hash, full_name or '', user[0]))

        conn.commit()
        conn.close()

        flash('Account setup complete! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
        
    # GET request (display page)
    email = request.args.get('email')
    token = request.args.get('token')
    return render_template('setup_account.html', email=email)

# Authentication routes with best practices
@auth.route('/register', methods=['GET', 'POST'])
def register():
    """Redirect to pricing since payment is required first"""
    flash('Choose a plan to get started', 'info')
    return redirect(url_for('pricing'))

@app.route('/login_success')
@login_required
def login_success():
    """Intermediate route after successful login for debugging"""
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>✅ Login Successful!</h2>
        <p><strong>User ID:</strong> {current_user.id}</p>
        <p><strong>Email:</strong> {current_user.email}</p>
        <p><strong>Name:</strong> {current_user.full_name or 'Not set'}</p>
        <p><strong>Verified:</strong> {current_user.is_verified}</p>
        <p><strong>Active:</strong> {current_user.is_active}</p>

        <h3>Next Steps:</h3>
        <ul>
            <li><a href="/dashboard">Go to Dashboard</a></li>
            <li><a href="/test_dashboard">Test Dashboard</a></li>
            <li><a href="/debug_session">Debug Session</a></li>
            <li><a href="/">Go Home (will redirect to dashboard)</a></li>
        </ul>

        <p style="color: #666; margin-top: 20px;">
        If clicking "Go to Dashboard" redirects you to the landing page, 
        there's an issue with the dashboard rendering.
        </p>
    </body>
    </html>
    """

@auth.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per hour per ip")
def login():
    """User login with improved verification handling"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'GET':
        return render_template('auth/login.html')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        if not email or not password:
            flash('Please enter both email and password', 'error')
            return render_template('auth/login.html')

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Get user with security checks
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    SELECT id, password_hash, is_verified, is_active, full_name,
                           failed_login_attempts, account_locked_until, email
                    FROM users WHERE LOWER(email) = LOWER(%s)
                ''', (email,))
            else:
                cursor.execute('''
                    SELECT id, password_hash, is_verified, is_active, full_name,
                           failed_login_attempts, account_locked_until, email
                    FROM users WHERE LOWER(email) = LOWER(?)
                ''', (email,))

            user_data = cursor.fetchone()

            if not user_data:
                flash('Invalid email or password', 'error')
                conn.close()
                return render_template('auth/login.html')

            # Extract user data
            if isinstance(user_data, dict):
                user_id = user_data['id']
                password_hash = user_data['password_hash']
                is_verified = user_data['is_verified']
                is_active = user_data['is_active']
                full_name = user_data['full_name']
                failed_attempts = user_data['failed_login_attempts']
                locked_until = user_data['account_locked_until']
                user_email = user_data['email']
            else:
                user_id = user_data[0]
                password_hash = user_data[1]
                is_verified = user_data[2]
                is_active = user_data[3]
                full_name = user_data[4]
                failed_attempts = user_data[5]
                locked_until = user_data[6]
                user_email = user_data[7] if len(user_data) > 7 else email

            # Check password first
            if not check_password_hash(password_hash, password):
                # Handle failed login attempts
                failed_attempts = (failed_attempts or 0) + 1

                if get_db_type() == 'postgresql':
                    cursor.execute('''
                        UPDATE users 
                        SET failed_login_attempts = %s, last_failed_login = %s
                        WHERE id = %s
                    ''', (failed_attempts, datetime.now(), user_id))
                else:
                    cursor.execute('''
                        UPDATE users 
                        SET failed_login_attempts = ?, last_failed_login = ?
                        WHERE id = ?
                    ''', (failed_attempts, datetime.now(), user_id))

                if failed_attempts >= 5:
                    locked_until = datetime.now() + timedelta(minutes=30)
                    if get_db_type() == 'postgresql':
                        cursor.execute('''
                            UPDATE users SET account_locked_until = %s
                            WHERE id = %s
                        ''', (locked_until, user_id))
                    else:
                        cursor.execute('''
                            UPDATE users SET account_locked_until = ?
                            WHERE id = ?
                        ''', (locked_until, user_id))
                    flash('Too many failed attempts. Account locked for 30 minutes.', 'error')
                else:
                    flash('Invalid email or password', 'error')

                conn.commit()
                conn.close()
                return render_template('auth/login.html')

            # Check if account is locked
            if locked_until and datetime.now() < datetime.fromisoformat(locked_until):
                flash('Account is temporarily locked due to too many failed attempts', 'error')
                conn.close()
                return render_template('auth/login.html')

            # Check if account is active
            if not is_active:
                flash('This account has been deactivated. Please contact support.', 'error')
                conn.close()
                return render_template('auth/login.html')

            # Handle verification with better UX
            if not is_verified:
                # If email system is not configured, auto-verify
                if not email_notifier.is_configured():
                    print(f"⚠️ Email not configured, auto-verifying user {email}")
                    if get_db_type() == 'postgresql':
                        cursor.execute('UPDATE users SET is_verified = true WHERE id = %s', (user_id,))
                    else:
                        cursor.execute('UPDATE users SET is_verified = 1 WHERE id = ?', (user_id,))
                    conn.commit()
                    is_verified = True
                else:
                    # Don't use HTML in flash messages, redirect with parameter instead
                    flash('Your email is not verified. Please check your inbox or use the link below to resend.', 'warning')
                    conn.close()
                    return redirect(url_for('auth.login', verification_needed=1))

            # Successful login
            user = create_user_session(user_data, email)
            login_user(user, remember=remember)

            print(f"✅ LOGIN: User {user.email} logged in successfully")
            print(f"   User ID: {user.id}")
            print(f"   Is authenticated: {current_user.is_authenticated}")

            # Update successful login
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    UPDATE users 
                    SET last_login = %s, failed_login_attempts = 0, account_locked_until = NULL
                    WHERE id = %s
                ''', (datetime.now(), user_id))
            else:
                cursor.execute('''
                    UPDATE users 
                    SET last_login = ?, failed_login_attempts = 0, account_locked_until = NULL
                    WHERE id = ?
                ''', (datetime.now(), user_id))

            conn.commit()
            conn.close()

            # Success message
            flash(f'Welcome back{", " + full_name if full_name else ""}!', 'success')

            if request.args.get('debug'):
                return redirect(url_for('login_success'))
            
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))

        except Exception as e:
            print(f"Login error: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred during login. Please try again.', 'error')
            if conn:
                conn.close()
            return render_template('auth/login.html')

    return render_template('auth/login.html')



# Add a simple test route first
@auth.route('/test')
def test_auth():
    return "Auth blueprint is working!"

@auth.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        session.clear()
        flash('You have been logged out successfully.', 'info')
    except Exception as e:
        print(f"Logout error: {e}")

    # Always redirect to the index/landing page, not login
    return redirect(url_for('index'))

@auth.route('/admin/resend_setup/<email>')
def resend_setup(email):
    """Admin route to resend setup email to a paid user"""

    # List of admin emails
    ADMIN_EMAILS = ['josh.matern@gmail.com']
    if not current_user.is_authenticated or current_user.email not in ADMIN_EMAILS:
        return "Unauthorized", 403

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Fetch user
        cursor.execute("""
            SELECT id, subscription_status
            FROM users
            WHERE LOWER(email) = LOWER(%s)
        """, (email,))
        user = cursor.fetchone()

        if not user:
            return f"User {email} not found", 404

        user_id = user[0]
        subscription_status = user[1]

        # Only allow if subscription is active
        if subscription_status != 'active':
            return f"User {email} does not have an active subscription", 400

        # Generate new setup token
        setup_token = secrets.token_urlsafe(32)
        setup_token_expiry = datetime.now() + timedelta(hours=24)

        # Update user in DB
        cursor.execute("""
            UPDATE users 
            SET setup_token = %s, setup_token_expiry = %s
            WHERE id = %s
        """, (setup_token, setup_token_expiry, user_id))
        conn.commit()

        # Generate setup link
        setup_link = f"https://screenshottracker.com/auth/complete-registration?email={email}&token={setup_token}"

        # HTML email content
        html_content = f"""
        <h2>Welcome to Screenshot Tracker!</h2>
        <p>Your subscription is active! Please complete your account setup:</p>
        <p><a href="{setup_link}">Set Your Password</a></p>
        <p>Or copy this link: {setup_link}</p>
        <p>This link expires in 24 hours.</p>
        """

        # Send email
        if email_notifier.is_configured():
            success = email_notifier.send_email(
                email,
                "Complete Your Screenshot Tracker Setup",
                html_content
            )
            if success:
                flash(f"✅ Setup email sent to {email}", "success")
            else:
                flash(f"❌ Failed to send setup email to {email}", "error")
        else:
            flash("⚠️ Email system not configured", "warning")

    except Exception as e:
        conn.rollback()
        flash(f"❌ Error: {e}", "error")
    finally:
        conn.close()

    return redirect("https://www.screenshottracker.com/dashboard")

@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Handle password reset with token"""
    token = request.args.get('token')

    if not token:
        flash('Invalid or missing reset token', 'error')
        return redirect(url_for('auth.login'))

    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Check if token is valid and not expired
    cursor.execute('''
        SELECT id, email FROM users 
        WHERE reset_token = ? AND reset_token_expiry > ?
    ''', (token, datetime.now()))

    user_data = cursor.fetchone()

    if not user_data:
        conn.close()
        flash('Invalid or expired reset link. Please request a new one.', 'error')
        return redirect(url_for('auth.forgot_password'))

    user_id, email = user_data

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate passwords
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('auth/reset_password.html', token=token)

        password_errors = validate_password(password)
        if password_errors:
            for error in password_errors:
                flash(error, 'error')
            return render_template('auth/reset_password.html', token=token)

        # Update password and clear reset token
        if password is not None:
            new_password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        else:
            raise ValueError("Password cannot be None")

        cursor.execute('''
            UPDATE users 
            SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL,
                failed_login_attempts = 0, account_locked_until = NULL
            WHERE id = ?
        ''', (new_password_hash, user_id))

        conn.commit()
        conn.close()

        flash('Your password has been reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('auth.login'))

    conn.close()
    return render_template('auth/reset_password.html', token=token)

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Request password reset"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()

        if not email or not validate_email(email):
            flash('Please enter a valid email address', 'error')
            return render_template('auth/forgot_password.html')

        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        try:
            cursor.execute('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', (email,))
            user = cursor.fetchone()

            if user:
                reset_token = secrets.token_urlsafe(32)
                expiry = datetime.now() + timedelta(hours=1)

                cursor.execute('''
                    UPDATE users SET reset_token = ?, reset_token_expiry = ?
                    WHERE LOWER(email) = LOWER(?)
                ''', (reset_token, expiry, email))
                conn.commit()

                # Send reset email
                if email_notifier.is_configured():
                    if email_notifier.send_password_reset_email(email, reset_token):
                        flash('Password reset link sent to your email!', 'success')
                    else:
                        flash('Error sending email. Please try again later.', 'error')
                else:
                    flash('Email system not configured. Contact support.', 'error')
            else:
                # Don't reveal if email exists for security
                flash('If an account exists with this email, you will receive a reset link.', 'info')

        except Exception as e:
            print(f"Forgot password error: {e}")
            flash('An error occurred. Please try again.', 'error')
        finally:
            conn.close()

        return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password.html')

@auth.route('/verify_email')
def verify_email():
    """Verify email with token - FIXED"""
    token = request.args.get('token')
    if not token:
        flash('Invalid verification link!', 'error')
        return redirect(url_for('auth.login'))

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Debug: Let's see what's happening
        print(f"🔍 Attempting to verify token: {token[:20]}...")

        # Check if token is valid and not expired
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT id, email FROM users 
                WHERE verification_token = %s AND 
                      (verification_token_expiry IS NULL OR verification_token_expiry > %s)
            ''', (token, datetime.now()))
        else:
            cursor.execute('''
                SELECT id, email FROM users 
                WHERE verification_token = ? AND 
                      (verification_token_expiry IS NULL OR verification_token_expiry > ?)
            ''', (token, datetime.now()))

        user_data = cursor.fetchone()

        if not user_data:
            # Let's check if token exists but is expired
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    SELECT id, email, verification_token_expiry 
                    FROM users WHERE verification_token = %s
                ''', (token,))
            else:
                cursor.execute('''
                    SELECT id, email, verification_token_expiry 
                    FROM users WHERE verification_token = ?
                ''', (token,))

            expired_user = cursor.fetchone()

            if expired_user:
                if isinstance(expired_user, dict):
                    expiry = expired_user['verification_token_expiry']
                    email = expired_user['email']
                else:
                    expiry = expired_user[2]
                    email = expired_user[1]

                print(f"❌ Token expired for {email}. Expired at: {expiry}")
                flash('Verification link has expired. Please request a new one.', 'error')
                conn.close()
                return redirect(url_for('auth.resend_verification'))
            else:
                print(f"❌ Token not found in database: {token[:20]}...")
                flash('Invalid verification link!', 'error')
                conn.close()
                return redirect(url_for('auth.login'))

        # Extract user data
        if isinstance(user_data, dict):
            user_id = user_data['id']
            email = user_data['email']
        else:
            user_id = user_data[0]
            email = user_data[1]

        print(f"✅ Valid token found for user {email} (ID: {user_id})")

        # Mark user as verified
        if get_db_type() == 'postgresql':
            cursor.execute('''
                UPDATE users 
                SET is_verified = true, 
                    verification_token = NULL,
                    verification_token_expiry = NULL 
                WHERE id = %s
            ''', (user_id,))
        else:
            cursor.execute('''
                UPDATE users 
                SET is_verified = 1, 
                    verification_token = NULL,
                    verification_token_expiry = NULL 
                WHERE id = ?
            ''', (user_id,))

        conn.commit()
        print(f"✅ User {email} verified successfully!")
        flash('Email verified successfully! You can now log in.', 'success')

    except Exception as e:
        print(f"❌ Email verification error: {e}")
        import traceback
        traceback.print_exc()
        flash('An error occurred during verification.', 'error')
    finally:
        conn.close()

    return redirect(url_for('auth.login'))

@auth.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    """Resend verification email - FIXED"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email:
            flash('Please enter your email address', 'error')
            return render_template('auth/resend_verification.html')

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Get user info
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    SELECT id, is_verified, verification_token 
                    FROM users 
                    WHERE LOWER(email) = LOWER(%s)
                ''', (email,))
            else:
                cursor.execute('''
                    SELECT id, is_verified, verification_token 
                    FROM users 
                    WHERE LOWER(email) = LOWER(?)
                ''', (email,))

            user_data = cursor.fetchone()

            if not user_data:
                # Don't reveal if email exists
                flash('If an account exists with this email, a verification link will be sent.', 'info')
                conn.close()
                return redirect(url_for('auth.login'))

            if isinstance(user_data, dict):
                user_id = user_data['id']
                is_verified = user_data['is_verified']
                old_token = user_data['verification_token']
            else:
                user_id = user_data[0]
                is_verified = user_data[1]
                old_token = user_data[2]

            print(f"🔍 Resending verification for user {email} (ID: {user_id})")
            print(f"   Old token: {old_token[:20] if old_token else 'None'}...")

            if is_verified:
                flash('This email is already verified. You can log in.', 'info')
                conn.close()
                return redirect(url_for('auth.login'))

            # Generate new verification token
            verification_token = secrets.token_urlsafe(32)
            token_expiry = datetime.now() + timedelta(hours=24)

            print(f"📝 Generated new token: {verification_token[:20]}...")
            print(f"   Expires at: {token_expiry}")

            # Update user with new token
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    UPDATE users 
                    SET verification_token = %s, verification_token_expiry = %s
                    WHERE id = %s
                ''', (verification_token, token_expiry, user_id))
            else:
                cursor.execute('''
                    UPDATE users 
                    SET verification_token = ?, verification_token_expiry = ?
                    WHERE id = ?
                ''', (verification_token, token_expiry, user_id))

            # Commit BEFORE sending email
            conn.commit()
            print(f"✅ Token saved to database for user {email}")

            # Send verification email
            if email_notifier.is_configured():
                print(f"📧 Sending verification email to {email}...")

                # Send synchronously for debugging
                success = email_notifier.send_verification_email(email, verification_token)

                if success:
                    print("✅ Verification email sent successfully")
                    flash('Verification email sent! Please check your inbox.', 'success')
                else:
                    print("❌ Failed to send verification email")
                    flash('Error sending email. Please try again later.', 'error')
            else:
                flash('Email system not configured. Contact support for manual verification.', 'warning')
                print("⚠️ Email system not configured")

            conn.close()
            return redirect(url_for('auth.login'))

        except Exception as e:
            print(f"❌ Error resending verification: {e}")
            import traceback
            traceback.print_exc()
            flash('Error sending verification email. Please try again.', 'error')
            if conn:
                conn.rollback()
                conn.close()

    return render_template('auth/resend_verification.html')

@auth.route('/complete-registration', methods=['GET', 'POST'])
def complete_registration():
    email = request.args.get('email', '').lower()
    token = request.args.get('token')

    if request.method == 'GET':
        # Show password setup form
        return render_template('complete_registration.html', token=token)

    if request.method == 'POST':
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        
        # Validate required fields
        if not password:
            flash('Password is required', 'error')
            return render_template('complete_registration.html', email=email, token=token)

        # Verify user has active subscription
        conn = get_db()
        cursor = conn.cursor()

        try:
            # Verify user exists with valid setup_token
            print(f"🔍 Looking up user with email: {email}")
            cursor.execute("""
                SELECT id, email, subscription_status, setup_token_expiry
                    FROM users
                    WHERE setup_token = %s
                    AND email = %s
                    AND setup_token_expiry > %s
                """, (token, email, datetime.now()))
            user = cursor.fetchone()

            if not user:
                print("❌ No user found with token and email")

                # Debug: Check if user exists at all
                cursor.execute("SELECT email, setup_token, setup_token_expiry FROM users WHERE email = %s", (email,))
                debug_user = cursor.fetchone()
                if debug_user:
                    print(f"   User exists: {debug_user[0]}")
                    print(f"   Token in DB: {debug_user[1][:20] if debug_user[1] else 'None'}...")
                    print(f"   Expiry: {debug_user[2]}")
                else:
                    print(f"   No user found with email {email}")

                flash('Invalid or expired registration link', 'error')
                return redirect(url_for('auth.login'))

            if user[2] != 'active':
                print(f"❌ User subscription not active: {user[2]}")
                flash('Invalid or expired registration link', 'error')
                return redirect(url_for('auth.login'))

            # Update user with password and full name
            password_hash = generate_password_hash(password)
            cursor.execute("""
                UPDATE users
                SET password_hash = %s,
                    full_name = %s,
                    is_verified = true,
                    setup_token = NULL,
                    setup_token_expiry = NULL
                WHERE id = %s
            """, (password_hash, full_name, user[0]))
            conn.commit()
            print(f"✅ User {email} registration completed successfully")
            
            flash('Registration complete! You can now log in.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            print(f"❌ Error during registration completion: {e}")
            conn.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('auth.login'))
        finally:
            conn.close()

    # Fallback (should never reach here)
    return redirect(url_for('auth.login'))

# ============= REGISTER BLUEPRINTS =============
app.register_blueprint(auth, url_prefix='/auth')

@app.route('/debug/products')
def debug_products():
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Check products table
        cursor.execute('SELECT COUNT(*) FROM products')
        result = cursor.fetchone()
        if result is not None:
            total_products = result[0]
        else:
            total_products = 0

        # Check products for current user
        cursor.execute('SELECT COUNT(*) FROM products WHERE user_id = %s OR user_email = %s', 
                       (current_user.id, current_user.email))
        result = cursor.fetchone()
        if result is not None:
            user_products = result[0]
        else:
            user_products = 0

        # Get recent products
        cursor.execute('''
            SELECT id, user_id, user_email, product_title, created_at 
            FROM products 
            ORDER BY created_at DESC 
            LIMIT 10
        ''')
        recent_products = cursor.fetchall()

        conn.close()

        html = f"""
        <h2>Products Debug</h2>
        <p><strong>Total Products:</strong> {total_products}</p>
        <p><strong>Your Products:</strong> {user_products}</p>
        <p><strong>Your User ID:</strong> {current_user.id}</p>
        <p><strong>Your Email:</strong> {current_user.email}</p>

        <h3>Recent Products:</h3>
        <ul>
        """

        for product in recent_products:
            html += f"<li>ID: {product[0]}, User ID: {product[1]}, Email: {product[2]}, Title: {product[3][:50]}...</li>"

        html += "</ul>"
        return html

    except Exception as e:
        return f"Debug Error: {str(e)}", 500

@app.route('/ping')
@csrf.exempt
@limiter.exempt
def ping():
    """Ultra-simple endpoint for testing"""
    return "pong", 200

@app.route('/status')
@csrf.exempt
@limiter.exempt
def status():
    """Status endpoint with basic info"""
    return jsonify({
        'status': 'running',
        'flask_version': flask.__version__,
        'time': datetime.now().isoformat()
    })

@app.route('/debug/persistence-test')
def persistence_test():
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Create test table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deployment_test (
                id SERIAL PRIMARY KEY,
                deployed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                deployment_count INTEGER DEFAULT 1
            )
        ''')

        # Count existing records
        cursor.execute('SELECT COUNT(*) FROM deployment_test')
        result = cursor.fetchone()
        count = result[0] if result is not None else 0

        # Add new record
        cursor.execute('INSERT INTO deployment_test (deployment_count) VALUES (%s)', (count + 1,))
        conn.commit()

        # Get all records
        cursor.execute('SELECT * FROM deployment_test ORDER BY deployed_at DESC')
        deployments = cursor.fetchall()
        conn.close()

        return f"""
        <h2>Persistence Test</h2>
        <p><strong>Total deployments recorded:</strong> {len(deployments)}</p>
        <p><strong>This should increase with each deployment, not reset to 1</strong></p>
        <h3>Deployment History:</h3>
        <ul>{''.join([f'<li>ID: {d[0]}, Count: {d[2]}, Time: {d[1]}</li>' for d in deployments])}</ul>
        """

    except Exception as e:
        return f"Persistence test error: {str(e)}"

@app.route('/debug/basic-env')
def debug_basic_env():
    """Check basic environment without database"""
    try:
        database_url = os.environ.get('DATABASE_URL')
        flask_env = os.environ.get('FLASK_ENV')

        # Test if we can import psycopg2
        try:
            import psycopg2
            psycopg2_available = True
        except ImportError:
            psycopg2_available = False

        # Test basic database connection without queries
        connection_test = "Unknown"
        try:
            if database_url:
                import psycopg2
                conn = psycopg2.connect(database_url)
                conn.close()
                connection_test = "SUCCESS"
            else:
                connection_test = "NO DATABASE_URL"
        except Exception as e:
            connection_test = f"FAILED: {str(e)}"

        return f"""
        <h2>Basic Environment Check</h2>
        <p><strong>DATABASE_URL exists:</strong> {'Yes' if database_url else 'No'}</p>
        <p><strong>DATABASE_URL preview:</strong> {database_url[:50] + '...' if database_url else 'Not set'}</p>
        <p><strong>FLASK_ENV:</strong> {flask_env}</p>
        <p><strong>psycopg2 available:</strong> {psycopg2_available}</p>
        <p><strong>Connection test:</strong> {connection_test}</p>
        """

    except Exception as e:
        return f"Basic env check failed: {str(e)}"

@app.route('/debug/check_screenshots/<int:product_id>')
@login_required
def debug_check_screenshots(product_id):
    """Debug route to check what screenshots exist for a product"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Check baseline screenshots
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT id, LENGTH(screenshot_data) as size, captured_at
                FROM baseline_screenshots
                WHERE product_id = %s
            ''', (product_id,))
        else:
            cursor.execute('''
                SELECT id, LENGTH(screenshot_data) as size, captured_at
                FROM baseline_screenshots
                WHERE product_id = ?
            ''', (product_id,))

        baseline = cursor.fetchone()

        # Check achievement screenshots
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT COUNT(*) as count, MIN(achieved_at) as first, MAX(achieved_at) as last
                FROM bestseller_screenshots
                WHERE product_id = %s
            ''', (product_id,))
        else:
            cursor.execute('''
                SELECT COUNT(*) as count, MIN(achieved_at) as first, MAX(achieved_at) as last
                FROM bestseller_screenshots
                WHERE product_id = ?
            ''', (product_id,))

        achievements = cursor.fetchone()

        # Get product info
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT product_title, created_at
                FROM products
                WHERE id = %s AND user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT product_title, created_at
                FROM products
                WHERE id = ? AND user_id = ?
            ''', (product_id, current_user.id))

        product = cursor.fetchone()

        conn.close()

        if not product:
            return "Product not found or unauthorized", 404

        # Extract values based on type
        if isinstance(product, dict):
            product_title = product['product_title']
            product_created = product['created_at']
        else:
            product_title = product[0]
            product_created = product[1]

        if baseline:
            if isinstance(baseline, dict):
                baseline_id = baseline['id']
                baseline_size = baseline['size']
                baseline_captured = baseline['captured_at']
            else:
                baseline_id = baseline[0]
                baseline_size = baseline[1]
                baseline_captured = baseline[2]
        else:
            baseline_id = None
            baseline_size = 0
            baseline_captured = None

        if achievements:
            if isinstance(achievements, dict):
                achievement_count = achievements['count']
                first_achievement = achievements['first']
                last_achievement = achievements['last']
            else:
                achievement_count = achievements[0]
                first_achievement = achievements[1]
                last_achievement = achievements[2]
        else:
            achievement_count = 0
            first_achievement = None
            last_achievement = None

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Screenshot Debug for Product #{product_id}</h2>
            <p><strong>Product:</strong> {product_title}</p>
            <p><strong>Added:</strong> {product_created}</p>

            <h3>Baseline Screenshot:</h3>
            <ul>
                <li><strong>Exists:</strong> {'✅ Yes' if baseline_id else '❌ No'}</li>
                <li><strong>ID:</strong> {baseline_id or 'N/A'}</li>
                <li><strong>Size:</strong> {baseline_size} bytes</li>
                <li><strong>Captured:</strong> {baseline_captured or 'N/A'}</li>
            </ul>

            <h3>Achievement Screenshots:</h3>
            <ul>
                <li><strong>Count:</strong> {achievement_count}</li>
                <li><strong>First:</strong> {first_achievement or 'N/A'}</li>
                <li><strong>Last:</strong> {last_achievement or 'N/A'}</li>
            </ul>

            <h3>Actions:</h3>
            <a href="/baseline_screenshot/{product_id}" target="_blank">View Baseline</a> | 
            <a href="/capture_baseline/{product_id}">Capture New Baseline</a> | 
            <a href="/fix_baseline/{product_id}">Move Achievement to Baseline</a> | 
            <a href="/dashboard">Dashboard</a>
        </body>
        </html>
        """

        return html

    except Exception as e:
        if conn:
            conn.close()
        import traceback
        return f"<pre>{traceback.format_exc()}</pre>", 500

@app.route('/admin/check_tokens')
@login_required
def check_tokens():
    """Debug route to check verification tokens"""
    ADMIN_EMAILS = ['amazonscreenshottracker@gmail.com']
    if current_user.email not in ADMIN_EMAILS:
        return "Unauthorized", 403

    conn = get_db()
    cursor = conn.cursor()

    if get_db_type() == 'postgresql':
        cursor.execute('''
            SELECT email, is_verified, verification_token, verification_token_expiry,
                   CASE 
                       WHEN verification_token_expiry > %s THEN 'Valid'
                       WHEN verification_token_expiry <= %s THEN 'Expired'
                       ELSE 'No Expiry Set'
                   END as status
            FROM users 
            WHERE is_verified = false OR is_verified IS NULL
            ORDER BY email
        ''', (datetime.now(), datetime.now()))
    else:
        cursor.execute('''
            SELECT email, is_verified, verification_token, verification_token_expiry,
                   CASE 
                       WHEN verification_token_expiry > ? THEN 'Valid'
                       WHEN verification_token_expiry <= ? THEN 'Expired'
                       ELSE 'No Expiry Set'
                   END as status
            FROM users 
            WHERE is_verified = 0 OR is_verified IS NULL
            ORDER BY email
        ''', (datetime.now(), datetime.now()))

    users = cursor.fetchall()
    conn.close()

    html = """
    <html>
    <head>
        <title>Verification Token Debug</title>
        <style>
            body { font-family: monospace; padding: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background: #f5f5f5; }
            .expired { color: red; }
            .valid { color: green; }
        </style>
    </head>
    <body>
        <h2>Verification Token Status</h2>
        <p>Current time: """ + str(datetime.now()) + """</p>
        <table>
            <tr>
                <th>Email</th>
                <th>Verified</th>
                <th>Token (first 20 chars)</th>
                <th>Expiry</th>
                <th>Status</th>
            </tr>
    """

    for user in users:
        if isinstance(user, dict):
            email = user['email']
            is_verified = user['is_verified']
            token = user['verification_token']
            expiry = user['verification_token_expiry']
            status = user['status']
        else:
            email = user[0]
            is_verified = user[1]
            token = user[2]
            expiry = user[3]
            status = user[4]

        token_preview = token[:20] + '...' if token else 'None'
        status_class = 'valid' if status == 'Valid' else 'expired' if status == 'Expired' else ''

        html += f"""
            <tr>
                <td>{email}</td>
                <td>{is_verified}</td>
                <td>{token_preview}</td>
                <td>{expiry}</td>
                <td class="{status_class}">{status}</td>
            </tr>
        """

    html += """
        </table>
        <br>
        <a href="/admin/manual_verify">Go to Manual Verify</a>
    </body>
    </html>
    """

    return html

@app.route('/admin/generate_verification_link/<email>')
def generate_verification_link(email):
    """Generate a manual verification link for testing"""
    ADMIN_EMAILS = ['amazonscreenshottracker@gmail.com']
    if current_user.email not in ADMIN_EMAILS:
        return "Unauthorized", 403

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT id, is_verified, verification_token 
                FROM users 
                WHERE LOWER(email) = LOWER(%s)
            ''', (email,))
        else:
            cursor.execute('''
                SELECT id, is_verified, verification_token 
                FROM users 
                WHERE LOWER(email) = LOWER(?)
            ''', (email,))

        user_data = cursor.fetchone()

        if not user_data:
            return f"User {email} not found", 404

        if isinstance(user_data, dict):
            user_id = user_data['id']
            is_verified = user_data['is_verified']
            existing_token = user_data['verification_token']
        else:
            user_id = user_data[0]
            is_verified = user_data[1]
            existing_token = user_data[2]

        if is_verified:
            return f"User {email} is already verified"

        # Generate new token
        verification_token = secrets.token_urlsafe(32)
        token_expiry = datetime.now() + timedelta(hours=24)

        # Update user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                UPDATE users 
                SET verification_token = %s, verification_token_expiry = %s
                WHERE id = %s
            ''', (verification_token, token_expiry, user_id))
        else:
            cursor.execute('''
                UPDATE users 
                SET verification_token = ?, verification_token_expiry = ?
                WHERE id = ?
            ''', (verification_token, token_expiry, user_id))

        conn.commit()
        conn.close()

        # Generate the link
        base_url = request.host_url.rstrip('/')
        verification_link = f"{base_url}/auth/verify_email?token={verification_token}"

        return f"""
        <html>
        <body style="font-family: monospace; padding: 20px;">
            <h2>Verification Link Generated</h2>
            <p><strong>Email:</strong> {email}</p>
            <p><strong>Token:</strong> {verification_token}</p>
            <p><strong>Expires:</strong> {token_expiry}</p>
            <p><strong>Link:</strong></p>
            <div style="background: #f5f5f5; padding: 10px; word-break: break-all;">
                <a href="{verification_link}">{verification_link}</a>
            </div>
            <br>
            <p>Copy this link and use it to verify the account.</p>
            <br>
            <a href="/admin/check_tokens">Back to Token Status</a>
        </body>
        </html>
        """

    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return f"Error: {str(e)}", 500

@app.route('/debug/email_config')
@login_required
def debug_email_config():
    """Check email configuration"""
    if current_user.email not in ['amazonscreenshottracker@gmail.com', 'josh.matern@gmail.com']:
        return "Unauthorized", 403

    return f"""
    <h2>Email Configuration Status</h2>
    <p><strong>SMTP_SERVER:</strong> {SMTP_SERVER or 'NOT SET'}</p>
    <p><strong>SMTP_PORT:</strong> {SMTP_PORT or 'NOT SET'}</p>
    <p><strong>SMTP_USERNAME:</strong> {'SET' if SMTP_USERNAME else 'NOT SET'}</p>
    <p><strong>SMTP_PASSWORD:</strong> {'SET' if SMTP_PASSWORD else 'NOT SET'}</p>
    <p><strong>SENDER_EMAIL:</strong> {SENDER_EMAIL or 'NOT SET'}</p>
    <p><strong>Is Configured:</strong> {email_notifier.is_configured()}</p>
    <br>
    <a href="/test_email_to_self">Test Send Email</a>
    """

@app.route('/emergency_stop')
@login_required
def emergency_stop():
    """Emergency stop all API usage"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Pause ALL products for ALL users (if you're admin)
        if current_user.email == 'josh.matern@gmail.com':
            if get_db_type() == 'postgresql':
                cursor.execute('UPDATE products SET active = false')
            else:
                cursor.execute('UPDATE products SET active = 0')

            total_paused = cursor.rowcount

            # Clear the user's API key to prevent any usage
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    UPDATE users 
                    SET scrapingbee_api_key = NULL 
                    WHERE id = %s
                ''', (current_user.id,))
            else:
                cursor.execute('''
                    UPDATE users 
                    SET scrapingbee_api_key = NULL 
                    WHERE id = ?
                ''', (current_user.id,))

            conn.commit()
            conn.close()

            # Kill the scheduler thread if it exists
            global scheduler_thread
            if 'scheduler_thread' in globals() and scheduler_thread is not None and scheduler_thread.is_alive():
                # Note: Can't actually kill thread safely in Python, but we can set a flag
                schedule.clear()  # Clear all scheduled jobs

            return f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px; background: #f8d7da;">
                <h1>🛑 EMERGENCY STOP ACTIVATED</h1>
                <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h2>Actions Taken:</h2>
                    <ul>
                        <li>✅ Paused {total_paused} products across all users</li>
                        <li>✅ Removed your ScrapingBee API key</li>
                        <li>✅ Cleared all scheduled jobs</li>
                    </ul>

                    <h2>No More API Calls Will Be Made!</h2>
                    <p>To resume:</p>
                    <ol>
                        <li>Re-add your API key in settings</li>
                        <li>Manually resume products you want to monitor</li>
                    </ol>
                </div>

                <a href="/dashboard" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                    Go to Dashboard
                </a>
            </body>
            </html>
            """
        else:
            # Non-admin: just pause their products
            if get_db_type() == 'postgresql':
                cursor.execute('UPDATE products SET active = false WHERE user_id = %s', (current_user.id,))
            else:
                cursor.execute('UPDATE products SET active = 0 WHERE user_id = ?', (current_user.id,))

            conn.commit()
            conn.close()

            flash('All your products have been paused', 'success')
            return redirect(url_for('dashboard'))

    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return f"Error: {str(e)}", 500


@app.route('/credit_leak_detector')
@login_required
def credit_leak_detector():
    """Enhanced credit leak detector with scheduler diagnostics"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # ... (keep existing queries for orphaned products, etc.) ...

        # Check scheduler status more thoroughly
        global scheduler_thread, scheduler_running

        scheduler_enabled = os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true'
        thread_exists = scheduler_thread is not None
        thread_alive = scheduler_thread.is_alive() if scheduler_thread else False

        # Get last check times
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN last_checked IS NOT NULL THEN 1 END) as checked_count,
                    MIN(last_checked) as oldest_check,
                    MAX(last_checked) as newest_check
                FROM products
                WHERE active = true
            ''')
        else:
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN last_checked IS NOT NULL THEN 1 END) as checked_count,
                    MIN(last_checked) as oldest_check,
                    MAX(last_checked) as newest_check
                FROM products
                WHERE active = 1
            ''')

        check_stats = cursor.fetchone()

        # Get products that are overdue
        current_time = datetime.now()
        check_threshold = current_time - timedelta(minutes=65)  # 5 minute grace period

        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT COUNT(*) as overdue_count
                FROM products
                WHERE active = true
                  AND (last_checked IS NULL OR last_checked < %s)
            ''', (check_threshold,))
        else:
            cursor.execute('''
                SELECT COUNT(*) as overdue_count
                FROM products
                WHERE active = 1
                  AND (last_checked IS NULL OR last_checked < ?)
            ''', (check_threshold,))

        overdue = cursor.fetchone()
        overdue_count = 0
        if overdue is not None:
            overdue_count = overdue['overdue_count'] if isinstance(overdue, dict) else overdue[0]

        # Build the HTML response
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; }}
                .danger {{ background: #f8d7da; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                .warning {{ background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                .success {{ background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                .info {{ background: #d1ecf1; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background: #f5f5f5; }}
            </style>
        </head>
        <body>
            <h1>🔍 Enhanced Credit Leak Detector</h1>

            <div class="{'danger' if not thread_alive and scheduler_enabled else 'success' if thread_alive else 'warning'}">
                <h2>Scheduler Status</h2>
                <p><strong>ENABLE_SCHEDULER env:</strong> {os.environ.get('ENABLE_SCHEDULER', 'Not Set')}</p>
                <p><strong>Should be enabled:</strong> {scheduler_enabled}</p>
                <p><strong>Thread object exists:</strong> {thread_exists}</p>
                <p><strong>Thread Alive:</strong> {'🔴 NO - NEEDS RESTART!' if not thread_alive and scheduler_enabled else '🟢 YES - Running' if thread_alive else '⚫ Disabled'}</p>
                <p><strong>Scheduler running flag:</strong> {scheduler_running}</p>
                <p><strong>Thread name:</strong> {scheduler_thread.name if scheduler_thread else 'None'}</p>
            </div>
        """

        if not thread_alive and scheduler_enabled:
            html += """
            <div class="danger">
                <h2>⚠️ SCHEDULER NOT RUNNING!</h2>
                <p>The scheduler should be running but it's not. Your products won't be checked automatically.</p>
                <p><strong>Action needed:</strong></p>
                <ol>
                    <li><a href="/ensure_scheduler" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                        🚀 Click here to start scheduler
                    </a></li>
                    <li>Then refresh this page to verify it's running</li>
                </ol>
            </div>
            """

        if overdue_count > 0:
            html += f"""
            <div class="warning">
                <h2>⏰ Overdue Products</h2>
                <p><strong>{overdue_count} products</strong> haven't been checked in over 65 minutes!</p>
                <p>This indicates the scheduler may have stopped working.</p>
            </div>
            """

        # Add more diagnostic info
        if check_stats:
            if isinstance(check_stats, dict):
                total = check_stats['total']
                checked = check_stats['checked_count']
                oldest = check_stats['oldest_check']
                newest = check_stats['newest_check']
            else:
                total = check_stats[0]
                checked = check_stats[1]
                oldest = check_stats[2]
                newest = check_stats[3]

            html += f"""
            <div class="info">
                <h2>Check Statistics</h2>
                <p><strong>Active products:</strong> {total}</p>
                <p><strong>Ever checked:</strong> {checked}</p>
                <p><strong>Never checked:</strong> {total - checked}</p>
                <p><strong>Oldest check:</strong> {oldest or 'Never'}</p>
                <p><strong>Newest check:</strong> {newest or 'Never'}</p>
                <p><strong>Current time:</strong> {current_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            """

        # Continue with the rest of the existing leak detector code...
        # (hourly usage table, recent checks, etc.)

        html += """
            <h2>Actions</h2>
            <a href="/ensure_scheduler" class="btn" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                🚀 Ensure Scheduler Running
            </a>
            <a href="/dashboard" class="btn" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-left: 10px;">
                📊 Dashboard
            </a>
        </body>
        </html>
        """

        conn.close()
        return html

    except Exception as e:
        if conn:
            conn.close()
        import traceback
        return f"<pre>{traceback.format_exc()}</pre>", 500

@app.route('/admin/resend_verification_to/<email>')
@login_required
def admin_resend_verification(email):
    """Admin tool to resend verification email"""
    if current_user.email not in ['josh.matern@gmail.com', 'amazonscreenshottracker@gmail.com']:
        return "Unauthorized", 403

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get user info
        if get_db_type() == 'postgresql':
            cursor.execute('SELECT id, is_verified FROM users WHERE email = %s', (email,))
        else:
            cursor.execute('SELECT id, is_verified FROM users WHERE email = ?', (email,))

        user = cursor.fetchone()
        if not user:
            return f"User {email} not found", 404

        user_id = user[0] if isinstance(user, tuple) else user['id']

        # Generate new token
        verification_token = secrets.token_urlsafe(32)
        token_expiry = datetime.now() + timedelta(hours=24)

        # Update user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                UPDATE users 
                SET verification_token = %s, verification_token_expiry = %s
                WHERE id = %s
            ''', (verification_token, token_expiry, user_id))
        else:
            cursor.execute('''
                UPDATE users 
                SET verification_token = ?, verification_token_expiry = ?
                WHERE id = ?
            ''', (verification_token, token_expiry, user_id))

        conn.commit()
        conn.close()

        # Send email
        success = email_notifier.send_verification_email(email, verification_token)

        if success:
            return f"""
            <h2>✅ Verification email sent to {email}</h2>
            <p>Token: {verification_token}</p>
            <p>Direct link: <a href="/auth/verify_email?token={verification_token}">Verify Now</a></p>
            """
        else:
            return f"Failed to send email to {email}", 500

    except Exception as e:
        if conn:
            conn.close()
        return f"Error: {str(e)}", 500

@app.route('/kill_scheduler')
@login_required
def kill_scheduler():
    """Attempt to kill the scheduler"""
    if current_user.email != 'josh.matern@gmail.com':
        return "Unauthorized", 403

    try:
        import schedule

        # Clear all scheduled jobs
        schedule.clear()

        # Set a flag to stop the scheduler
        global SCHEDULER_ENABLED
        SCHEDULER_ENABLED = False

        # Try to stop the thread (won't actually kill it, but will prevent new jobs)
        global scheduler_thread
        if 'scheduler_thread' in globals():
            # Can't actually stop the thread, but clearing jobs should help
            pass

        return """
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h1>✅ Scheduler Killed</h1>
            <p>All scheduled jobs have been cleared.</p>
            <p>The scheduler thread cannot be forcibly stopped in Python, but it will no longer execute jobs.</p>

            <h2>To permanently disable:</h2>
            <ol>
                <li>Add ENABLE_SCHEDULER=false to Railway environment variables</li>
                <li>Redeploy the application</li>
            </ol>

            <a href="/credit_leak_detector">Back to Leak Detector</a>
        </body>
        </html>
        """

    except Exception as e:
        return "Error: {str(e)}", 500

@app.route('/debug/db-connection')
def debug_db_connection():
    database_url = os.environ.get('DATABASE_URL', 'NOT SET')

    # Check if it's really PostgreSQL
    is_postgresql = 'postgresql' in database_url.lower()

    if is_postgresql:
        try:
            conn = get_db()
            cursor = conn.cursor()

            # Get PostgreSQL version and database name
            cursor.execute('SELECT version(), current_database()')
            db_info = cursor.fetchone()

            # Check if tables exist
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name
            """)
            tables = cursor.fetchall()

            conn.close()

            return f"""
            <h2>Database Connection Debug</h2>
            <p><strong>Database URL:</strong> {database_url[:50]}...</p>
            <p><strong>PostgreSQL:</strong> {is_postgresql}</p>
            <p><strong>Version:</strong> {db_info[0][:100] if db_info else 'Unknown'}</p>
            <p><strong>Database:</strong> {db_info[1] if db_info else 'Unknown'}</p>
            <p><strong>Tables:</strong> {[t[0] for t in tables]}</p>
            """

        except Exception as e:
            return f"Database error: {str(e)}"
    else:
        return f"Using SQLite (not PostgreSQL): {database_url}"


@app.route('/test-email')
@login_required
def test_email():
    """Test email configuration"""
    if current_user.email != 'josh.matern@gmail.com':  # Replace with your email
        return "Unauthorized", 403

    try:
        # Try to send a test email
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import smtplib

        msg = MIMEMultipart()
        msg['From'] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg['To'] = current_user.email
        msg['Subject'] = "Test Email - Amazon Screenshot Tracker"

        body = "If you're reading this, email configuration is working!"
        msg.attach(MIMEText(body, 'plain'))

        if SMTP_USERNAME is None or SMTP_PASSWORD is None:
            raise ValueError("SMTP_USERNAME and SMTP_PASSWORD must be set in environment variables")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)

        return "Test email sent! Check your inbox."
    except Exception as e:
        return f"Email test failed: {str(e)}", 500

@app.route('/')
def index():
    """Landing page - properly handle authenticated users"""
    print("🔍 INDEX: Route called")

    try:
        if current_user.is_authenticated:
            print(f"🔍 INDEX: Authenticated user: {current_user.email} (ID: {current_user.id})")
            # Call dashboard_view directly instead of redirecting
            return dashboard_view()
        else:
            print("🔍 INDEX: Showing landing page for anonymous user")
            return render_template('landing.html')

    except Exception as e:
        print(f"❌ INDEX: Error: {e}")
        import traceback
        traceback.print_exc()

        # If there's an error, show landing page
        return render_template('landing.html')

@app.route('/test')
def test_route():
    """Simple test route to verify basic functionality"""
    print("🔍 TEST: Simple test route called")
    return "✅ Test route working! App is alive.", 200

@app.route('/debug/baseline_screenshots')
@login_required
def debug_baseline_screenshots():
    """Debug route to check baseline screenshots"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get all products for user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT p.id, p.product_title, b.id as baseline_id, 
                       LENGTH(b.screenshot_data) as screenshot_size
                FROM products p
                LEFT JOIN baseline_screenshots b ON p.id = b.product_id
                WHERE p.user_id = %s
                ORDER BY p.created_at DESC
            ''', (current_user.id,))
        else:
            cursor.execute('''
                SELECT p.id, p.product_title, b.id as baseline_id, 
                       LENGTH(b.screenshot_data) as screenshot_size
                FROM products p
                LEFT JOIN baseline_screenshots b ON p.id = b.product_id
                WHERE p.user_id = ?
                ORDER BY p.created_at DESC
            ''', (current_user.id,))

        products = cursor.fetchall()
        conn.close()

        html = """
        <html>
        <body style="font-family: monospace; padding: 20px;">
            <h2>Baseline Screenshots Debug</h2>
            <table border="1" cellpadding="10">
                <tr>
                    <th>Product ID</th>
                    <th>Title</th>
                    <th>Has Baseline?</th>
                    <th>Screenshot Size</th>
                    <th>Action</th>
                </tr>
        """

        for product in products:
            if isinstance(product, dict):
                prod_id = product['id']
                title = product['product_title']
                baseline_id = product['baseline_id']
                size = product['screenshot_size']
            else:
                prod_id = product[0]
                title = product[1]
                baseline_id = product[2]
                size = product[3]

            has_baseline = "✅ Yes" if baseline_id else "❌ No"
            size_display = f"{size} bytes" if size else "N/A"

            html += f"""
                <tr>
                    <td>{prod_id}</td>
                    <td>{title[:50]}...</td>
                    <td>{has_baseline}</td>
                    <td>{size_display}</td>
                    <td>
                        <a href="/baseline_screenshot/{prod_id}" target="_blank">View</a> |
                        <a href="/capture_baseline/{prod_id}">Capture Now</a>
                    </td>
                </tr>
            """

        html += """
            </table>
            <br>
            <a href="/dashboard">Back to Dashboard</a>
        </body>
        </html>
        """

        return html

    except Exception as e:
        if conn:
            conn.close()
        return f"Error: {str(e)}", 500


@app.route('/capture_baseline/<int:product_id>')
@login_required
def capture_baseline(product_id):
    """Manually capture baseline screenshot for a product"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Verify product belongs to user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT product_url FROM products 
                WHERE id = %s AND user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT product_url FROM products 
                WHERE id = ? AND user_id = ?
            ''', (product_id, current_user.id))

        result = cursor.fetchone()
        if not result:
            conn.close()
            return "Product not found or unauthorized", 404

        if isinstance(result, dict):
            product_url = result['product_url']
        else:
            product_url = result[0]

        # Capture screenshot
        user_monitor = AmazonMonitor.for_user(current_user.id)
        scrape_result = user_monitor.scrape_amazon_page(product_url)

        if not scrape_result.get('success'):
            conn.close()
            return f"Scraping failed: {scrape_result.get('error')}", 500

        if scrape_result.get('screenshot'):
            # Convert to base64 before storing
            screenshot_base64 = base64.b64encode(scrape_result['screenshot']).decode('utf-8')
            # Extract product info
            product_info = user_monitor.extract_product_info(scrape_result['html'])

            # Save baseline screenshot
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    INSERT INTO baseline_screenshots 
                    (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (product_id) DO UPDATE SET
                    screenshot_data = EXCLUDED.screenshot_data,
                    initial_rank = EXCLUDED.initial_rank,
                    initial_category = EXCLUDED.initial_category,
                    captured_at = EXCLUDED.captured_at
                ''', (product_id, screenshot_base64, 
                      product_info.get('rank'), product_info.get('category'), 
                      datetime.now()))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO baseline_screenshots 
                    (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (product_id, scrape_result['screenshot'], 
                      product_info.get('rank'), product_info.get('category'), 
                      datetime.now()))

            conn.commit()
            conn.close()

            return f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>✅ Baseline Screenshot Captured!</h2>
                <p>Product ID: {product_id}</p>
                <p>Rank: {product_info.get('rank', 'N/A')}</p>
                <p>Category: {product_info.get('category', 'N/A')}</p>
                <br>
                <a href="/baseline_screenshot/{product_id}" target="_blank">View Screenshot</a> |
                <a href="/debug/baseline_screenshots">Back to Debug</a> |
                <a href="/dashboard">Dashboard</a>
            </body>
            </html>
            """
        else:
            conn.close()
            return "No screenshot captured (ScrapingBee might not be configured for screenshots)", 500

    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return f"Error: {str(e)}", 500


@app.route('/test_scrapingbee_screenshot')
@login_required
def test_scrapingbee_screenshot():
    """Test if ScrapingBee can capture screenshots - FIXED"""
    try:
        # Test with Amazon homepage
        test_url = "https://www.amazon.com"

        user_monitor = AmazonMonitor.for_user(current_user.id)

        # Check if API key exists
        if not user_monitor.api_key:
            return """
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>❌ No API Key</h2>
                <p>Please configure your ScrapingBee API key first.</p>
                <a href="/settings">Go to Settings</a>
            </body>
            </html>
            """

        result = user_monitor.scrape_amazon_page(test_url)

        # Handle None values safely
        html_content = result.get('html', '')
        screenshot_data = result.get('screenshot')

        html = f"""
        <html>
        <body style="font-family: monospace; padding: 20px;">
            <h2>ScrapingBee Screenshot Test</h2>
            <p><strong>Test URL:</strong> {test_url}</p>
            <p><strong>API Key (first 10):</strong> {user_monitor.api_key[:10] if user_monitor.api_key else 'None'}...</p>
            <p><strong>Success:</strong> {result.get('success', False)}</p>
            <p><strong>HTML Length:</strong> {len(html_content) if html_content else 0}</p>
            <p><strong>Screenshot Present:</strong> {bool(screenshot_data)}</p>
            <p><strong>Screenshot Length:</strong> {len(screenshot_data) if screenshot_data else 0}</p>

            <h3>Error (if any):</h3>
            <pre>{result.get('error', 'None')}</pre>

            <h3>HTML Preview (first 500 chars):</h3>
            <pre>{html_content[:500] if html_content else 'No HTML content'}...</pre>

            <h3>Screenshot Data Preview:</h3>
            <pre>{screenshot_data[:100] if screenshot_data else 'No screenshot data'}...</pre>

            <br>
            <h3>Actions:</h3>
            <a href="/test_product_scrape">Test Product Scrape</a> | 
            <a href="/dashboard">Back to Dashboard</a>
        </body>
        </html>
        """

        return html

    except Exception as e:
        import traceback
        return f"""
        <html>
        <body style="font-family: monospace; padding: 20px;">
            <h2>Test Failed</h2>
            <pre>{traceback.format_exc()}</pre>
            <a href="/dashboard">Back to Dashboard</a>
        </body>
        </html>
        """, 500


@app.route('/test_product_scrape')
@login_required
def test_product_scrape():
    """Test scraping a specific product"""
    # Use a known Amazon product for testing
    test_url = "https://www.amazon.com/dp/B08N5WRWNW"  # Echo Dot example

    try:
        user_monitor = AmazonMonitor.for_user(current_user.id)

        if not user_monitor.api_key:
            return "No API key configured", 400

        result = user_monitor.scrape_amazon_page(test_url)

        if result.get('success'):
            product_info = user_monitor.extract_product_info(result.get('html', ''))

            return f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>Product Scrape Test</h2>
                <h3>Scrape Result:</h3>
                <ul>
                    <li><strong>Success:</strong> {result.get('success')}</li>
                    <li><strong>HTML Length:</strong> {len(result.get('html', ''))}</li>
                    <li><strong>Screenshot:</strong> {bool(result.get('screenshot'))}</li>
                </ul>

                <h3>Product Info Extracted:</h3>
                <ul>
                    <li><strong>Title:</strong> {product_info.get('title', 'Not found')}</li>
                    <li><strong>Rank:</strong> {product_info.get('rank', 'Not found')}</li>
                    <li><strong>Category:</strong> {product_info.get('category', 'Not found')}</li>
                    <li><strong>Is Bestseller:</strong> {product_info.get('is_bestseller', False)}</li>
                </ul>

                <h3>Raw HTML Sample:</h3>
                <textarea style="width: 100%; height: 300px;">{result.get('html', '')[:2000]}</textarea>

                <br><br>
                <a href="/dashboard">Back to Dashboard</a>
            </body>
            </html>
            """
        else:
            return f"Scrape failed: {result.get('error')}", 500

    except Exception as e:
        import traceback
        return f"Test failed: {traceback.format_exc()}", 500

@app.route('/test_resend')
@login_required
def test_resend():
    if current_user.email not in ['josh.matern@gmail.com']:
        return "Unauthorized", 403

    success = email_notifier._send_via_resend(
        current_user.email,
        "Test Email",
        "<h2>Test</h2><p>This is a test from Screenshot Tracker.</p>"
    )

    return f"Email {'sent' if success else 'failed'}! Check logs for details."

@app.route('/fix_product/<int:product_id>')
@login_required
def fix_product(product_id):
    """Re-scrape a product to fix missing information"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get product URL
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT product_url FROM products 
                WHERE id = %s AND user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT product_url FROM products 
                WHERE id = ? AND user_id = ?
            ''', (product_id, current_user.id))

        result = cursor.fetchone()
        if not result:
            conn.close()
            return "Product not found", 404

        product_url = result['product_url'] if isinstance(result, dict) else result[0]

        # Re-scrape the product
        user_monitor = AmazonMonitor.for_user(current_user.id)
        scrape_result = user_monitor.scrape_amazon_page(product_url)

        if scrape_result.get('success'):
            product_info = user_monitor.extract_product_info(scrape_result.get('html', ''))

            # Update product information
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    UPDATE products 
                    SET product_title = %s, current_rank = %s, 
                        current_category = %s, is_bestseller = %s, 
                        last_checked = %s
                    WHERE id = %s
                ''', (
                    product_info.get('title', 'Unknown Product'),
                    product_info.get('rank'),
                    product_info.get('category'),
                    product_info.get('is_bestseller', False),
                    datetime.now(),
                    product_id
                ))
            else:
                cursor.execute('''
                    UPDATE products 
                    SET product_title = ?, current_rank = ?, 
                        current_category = ?, is_bestseller = ?, 
                        last_checked = ?
                    WHERE id = ?
                ''', (
                    product_info.get('title', 'Unknown Product'),
                    product_info.get('rank'),
                    product_info.get('category'),
                    product_info.get('is_bestseller', False),
                    datetime.now(),
                    product_id
                ))

            # Save baseline screenshot if we got one and don't have one yet
            if scrape_result.get('screenshot'):
                # Check if baseline exists
                if get_db_type() == 'postgresql':
                    cursor.execute('SELECT id FROM baseline_screenshots WHERE product_id = %s', (product_id,))
                else:
                    cursor.execute('SELECT id FROM baseline_screenshots WHERE product_id = ?', (product_id,))

                if not cursor.fetchone():
                    # No baseline exists, save it
                    if get_db_type() == 'postgresql':
                        cursor.execute('''
                            INSERT INTO baseline_screenshots 
                            (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                            VALUES (%s, %s, %s, %s, %s)
                        ''', (product_id, scrape_result['screenshot'], 
                              product_info.get('rank'), product_info.get('category'), 
                              datetime.now()))
                    else:
                        cursor.execute('''
                            INSERT INTO baseline_screenshots 
                            (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (product_id, scrape_result['screenshot'], 
                              product_info.get('rank'), product_info.get('category'), 
                              datetime.now()))

            conn.commit()
            conn.close()

            flash(f'Product updated: {product_info.get("title", "Unknown")[:50]}...', 'success')
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash(f'Failed to update product: {scrape_result.get("error")}', 'error')
            return redirect(url_for('dashboard'))

    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        flash(f'Error updating product: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/fix_baseline/<int:product_id>')
@login_required
def fix_baseline(product_id):
    """Move the first achievement screenshot to be the baseline"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Verify ownership
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT id FROM products 
                WHERE id = %s AND user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT id FROM products 
                WHERE id = ? AND user_id = ?
            ''', (product_id, current_user.id))

        if not cursor.fetchone():
            conn.close()
            return "Product not found or unauthorized", 404

        # Get the first achievement screenshot
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT screenshot_data, rank_achieved, category, achieved_at
                FROM bestseller_screenshots
                WHERE product_id = %s
                ORDER BY achieved_at ASC
                LIMIT 1
            ''', (product_id,))
        else:
            cursor.execute('''
                SELECT screenshot_data, rank_achieved, category, achieved_at
                FROM bestseller_screenshots
                WHERE product_id = ?
                ORDER BY achieved_at ASC
                LIMIT 1
            ''', (product_id,))

        achievement = cursor.fetchone()

        if achievement:
            if isinstance(achievement, dict):
                screenshot_data = achievement['screenshot_data']
                rank = achievement['rank_achieved']
                category = achievement['category']
                captured_at = achievement['achieved_at']
            else:
                screenshot_data = achievement[0]
                rank = achievement[1]
                category = achievement[2]
                captured_at = achievement[3]

            # Insert as baseline
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    INSERT INTO baseline_screenshots 
                    (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (product_id) DO UPDATE SET
                    screenshot_data = EXCLUDED.screenshot_data,
                    initial_rank = EXCLUDED.initial_rank,
                    initial_category = EXCLUDED.initial_category,
                    captured_at = EXCLUDED.captured_at
                ''', (product_id, screenshot_data, rank, category, captured_at))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO baseline_screenshots 
                    (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (product_id, screenshot_data, rank, category, captured_at))

            conn.commit()
            conn.close()

            flash('Baseline screenshot has been set from achievement screenshot', 'success')
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            return "No achievement screenshots found to use as baseline", 404

    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        flash(f'Error setting baseline: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/add_product_form')
@login_required
def add_product_form():
    """Show the add product form"""
    return render_template('add_product.html')

@app.route('/add_product', methods=['POST'])
#@limiter.limit("10 per minute")
@login_required
def add_product():
    print(f"🔍 Adding product for user {current_user.email} (ID: {current_user.id})")
    #MAX_PRODUCTS_PER_USER = 5

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get user's subscription info
        if get_db_type() == 'postgresql':
            cursor.execute("""
                SELECT subscription_tier, subscription_status, 
                       subscription_expires, max_products
                FROM users WHERE id = %s
            """, (current_user.id,))
        else:
            cursor.execute("""
                SELECT subscription_tier, subscription_status, 
                       subscription_expires, max_products
                FROM users WHERE id = ?
            """, (current_user.id,))

        user_data = cursor.fetchone()

        # Check if user_data exists before accessing
        if not user_data:
            flash('User account not found', 'error')
            conn.close()
            return redirect(url_for('dashboard'))

        # Handle both dict and tuple responses
        if isinstance(user_data, dict):
            subscription_tier = user_data.get('subscription_tier', 'free')  # Add default
            subscription_status = user_data.get('subscription_status', 'inactive')
            subscription_expires = user_data.get('subscription_expires')
            max_products = user_data.get('max_products', 0)
        else:
            subscription_tier = user_data[0] if len(user_data) > 0 else 'free'
            subscription_status = user_data[1] if len(user_data) > 1 else 'inactive'
            subscription_expires = user_data[2] if len(user_data) > 2 else None
            max_products = user_data[3] if len(user_data) > 3 else 0

        print(f"📊 User subscription: tier={subscription_tier}, status={subscription_status}, max={max_products}")


        # Check subscription status
        if subscription_status != 'active':
            flash('Please subscribe to add products. Visit our pricing page.', 'error')
            conn.close()
            return redirect(url_for('pricing'))

        if subscription_expires and isinstance(subscription_expires, datetime) and subscription_expires < datetime.now():
            flash('Your subscription has expired. Please renew.', 'error')
            conn.close()
            return redirect(url_for('pricing'))

        # Check product limit
        if not max_products:
            max_products = 0  # Default if NULL

        if get_db_type() == 'postgresql':
            cursor.execute(
                "SELECT COUNT(*) FROM products WHERE user_id = %s",
                (current_user.id,)
            )
        else:
            cursor.execute(
                "SELECT COUNT(*) FROM products WHERE user_id = ?",
                (current_user.id,)
            )

        count_result = cursor.fetchone()
        
        if isinstance(count_result, dict):
            current_count = count_result.get('count', 0)
        elif isinstance(count_result, (tuple, list)):
            current_count = count_result[0] if count_result[0] is not None else 0
        else:
            current_count = 0

        print(f"📊 Current products: {current_count}, Max allowed: {max_products}")

        if current_count >= max_products:
            flash(f'You have {current_count} products (limit: {max_products}). Please upgrade or remove a product.', 'error')
            conn.close()
            return redirect(url_for('dashboard'))
            
        url = request.form.get('url', '').strip()
        target_categories_input = request.form.get('target_categories', '').strip()

        if not url or 'amazon.' not in url.lower():
            flash('Please provide a valid Amazon product URL', 'error')
            conn.close()
            return redirect(url_for('add_product_form'))

        print(f"📦 Scraping product: {url}")

        # Scrape product
        try:
            user_monitor = AmazonMonitor(SCRAPINGBEE_API_KEY)  # Use global key directly
            scrape_result = user_monitor.scrape_amazon_page(url)
        except Exception as scrape_error:
            print(f"❌ Scraping error: {scrape_error}")
            flash(f'Error accessing product: {str(scrape_error)}', 'error')
            conn.close()
            return redirect(url_for('add_product_form'))

        if not scrape_result.get('success'):
            error_msg = scrape_result.get("error", "Unknown error")

            if "429" in str(error_msg) or "rate limit" in error_msg.lower():
                flash('ScrapingBee rate limit reached. Please wait a moment and try again.', 'warning')
            elif "401" in str(error_msg) or "unauthorized" in error_msg.lower():
                flash('Invalid ScrapingBee API key. Please check your settings.', 'error')
                conn.close()
                return redirect(url_for('settings'))
            elif "402" in str(error_msg):
                flash('Insufficient ScrapingBee credits. Please check your account.', 'error')
            else:
                flash(f'Error accessing product: {error_msg}', 'error')

            conn.close()
            return redirect(url_for('add_product_form'))

        # Extract product info
        product_info = user_monitor.extract_product_info(scrape_result.get('html', ''))

        print(f"📋 Product info extracted: {product_info}")

        # Insert product
        if get_db_type() == 'postgresql':
            cursor.execute('''
                INSERT INTO products (user_id, user_email, product_url, product_title, 
                                    current_rank, current_category, is_bestseller, last_checked)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                current_user.id, 
                current_user.email, 
                url,
                product_info.get('title', 'Unknown Product'),
                product_info.get('rank'),
                product_info.get('category'),
                product_info.get('is_bestseller', False),
                datetime.now()
            ))
            result = cursor.fetchone()

            if result:
                if isinstance(result, dict):
                    product_id = result['id']
                elif isinstance(result, (tuple, list)):
                    product_id = result[0]
                else:
                    product_id = result
            else:
                # Fallback: query for the product we just inserted
                cursor.execute('''
                    SELECT id FROM products 
                    WHERE user_id = %s AND product_url = %s 
                    ORDER BY id DESC LIMIT 1
                ''', (current_user.id, url))
                fallback_result = cursor.fetchone()
                if fallback_result:
                    product_id = fallback_result['id'] if isinstance(fallback_result, dict) else fallback_result[0]
                else:
                    raise ValueError("Failed to get product ID after insertion")
                    
        else:
            cursor.execute('''
                INSERT INTO products (user_id, user_email, product_url, product_title, 
                                    current_rank, current_category, is_bestseller, last_checked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                current_user.id, 
                current_user.email, 
                url,
                product_info.get('title', 'Unknown Product'),
                product_info.get('rank'),
                product_info.get('category'),
                product_info.get('is_bestseller', False),
                datetime.now()
            ))
            product_id = cursor.lastrowid

        if not product_id:
            raise ValueError("Failed to get product ID after insertion")

        print(f"✅ Product saved with ID: {product_id}")
        conn.commit()

        # Process target categories if provided
        if target_categories_input:
            categories = [cat.strip() for cat in target_categories_input.split(',')]
            for category_str in categories:
                if ':' in category_str:
                    category_name, target_rank = category_str.split(':', 1)
                    try:
                        target_rank = int(target_rank)
                    except ValueError:
                        target_rank = 1
                else:
                    category_name = category_str
                    target_rank = 1

                if category_name:
                    if get_db_type() == 'postgresql':
                        cursor.execute('''
                            INSERT INTO target_categories 
                            (product_id, category_name, target_rank, created_at)
                            VALUES (%s, %s, %s, %s)
                        ''', (product_id, category_name.strip(), target_rank, datetime.now()))
                    else:
                        cursor.execute('''
                            INSERT INTO target_categories 
                            (product_id, category_name, target_rank, created_at)
                            VALUES (?, ?, ?, ?)
                        ''', (product_id, category_name.strip(), target_rank, datetime.now()))

                    print(f"🎯 Added target category: {category_name} (target rank: {target_rank})")

            conn.commit()

        # Save baseline screenshot if available
        if scrape_result.get('screenshot'):
            # We already have it from the initial scrape
            screenshot_data = scrape_result['screenshot']
        else:
            # Try to get just the screenshot
            print("📸 Attempting to capture baseline screenshot...")
            try:
                screenshot_result = user_monitor.scrape_amazon_page(url, need_screenshot=True)
                screenshot_data = screenshot_result.get('screenshot')
            except:
                screenshot_data = None
        if screenshot_data:
            print(f"📸 Saving baseline screenshot (length: {len(scrape_result['screenshot'])})")

            # Convert binary screenshot to base64 for database storage
            import base64
            screenshot_base64 = base64.b64encode(scrape_result['screenshot']).decode('utf-8')
            print(f"📸 Converted to base64 (length: {len(screenshot_base64)})")

            if get_db_type() == 'postgresql':
                cursor.execute('''
                    INSERT INTO baseline_screenshots 
                    (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (product_id) DO UPDATE SET
                    screenshot_data = EXCLUDED.screenshot_data,
                    captured_at = EXCLUDED.captured_at
                ''', (product_id, screenshot_base64, product_info.get('rank'),
                      product_info.get('category'), datetime.now()))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO baseline_screenshots 
                    (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (product_id, screenshot_base64, product_info.get('rank'),
                      product_info.get('category'), datetime.now()))
            conn.commit()

            print("✅ Baseline screenshot saved as base64")
            flash(f'✅ Successfully added "{product_info.get("title", "Product")[:50]}..." with screenshot!', 'success')
        else:
            print("📸 Screenshot will be captured in background.")
            flash('Product added! Screenshot will be captured shortly.', 'info')

        conn.close()

        flash(f'✅ Successfully added "{product_info.get("title", "Product")[:50]}..."', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        print(f"❌ Error in add_product: {e}")
        print(f"❌ Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()

        if conn:
            try:
                conn.rollback()
            except:
                pass
            try:
                conn.close()
            except:
                pass

        # More specific error messages
        if "constraint" in str(e).lower():
            flash('This product may already exist in your account.', 'error')
        elif "timeout" in str(e).lower():
            flash('Request timed out. Please try again.', 'error')
        else:
            flash(f'Error adding product: {str(e)[:100]}', 'error')

        return redirect(url_for('add_product_form'))

@app.route('/pricing')
def pricing():
    """Pricing page with Stripe price IDs"""
    return render_template('pricing.html',
        author_weekly_price_id=os.environ.get('STRIPE_AUTHOR_WEEKLY_PRICE'),
        author_monthly_price_id=os.environ.get('STRIPE_AUTHOR_MONTHLY_PRICE'),
        author_yearly_price_id=os.environ.get('STRIPE_AUTHOR_YEARLY_PRICE'),
        publisher_weekly_price_id=os.environ.get('STRIPE_PUBLISHER_WEEKLY_PRICE'),
        publisher_monthly_price_id=os.environ.get('STRIPE_PUBLISHER_MONTHLY_PRICE'),
        publisher_yearly_price_id=os.environ.get('STRIPE_PUBLISHER_YEARLY_PRICE')
    )

@app.route('/cancel_subscription', methods=['GET', 'POST'])
@login_required
def cancel_subscription():
    """Cancel subscription page with password confirmation"""
    if request.method == 'POST':
        password = request.form.get('password')

        if not password:
            flash('Please enter your password to confirm cancellation', 'error')
            return render_template('cancel_subscription.html')

        # Verify password
        conn = get_db()
        cursor = conn.cursor()

        if get_db_type() == 'postgresql':
            cursor.execute('SELECT password_hash, stripe_subscription_id FROM users WHERE id = %s', (current_user.id,))
        else:
            cursor.execute('SELECT password_hash, stripe_subscription_id FROM users WHERE id = ?', (current_user.id,))

        user_data = cursor.fetchone()

        if not user_data:
            conn.close()
            flash('User not found', 'error')
            return redirect(url_for('dashboard'))

        password_hash = user_data[0] if isinstance(user_data, tuple) else user_data['password_hash']
        subscription_id = user_data[1] if isinstance(user_data, tuple) else user_data['stripe_subscription_id']

        if not check_password_hash(password_hash, password):
            conn.close()
            flash('Incorrect password', 'error')
            return render_template('cancel_subscription.html')

        # Cancel in Stripe
        try:
            if subscription_id:
                stripe.Subscription.delete(subscription_id)
                print(f"✅ Cancelled Stripe subscription {subscription_id}")

            # Update database
            if get_db_type() == 'postgresql':
                cursor.execute("""
                    UPDATE users 
                    SET subscription_status = 'cancelled',
                        max_products = 0
                    WHERE id = %s
                """, (current_user.id,))
            else:
                cursor.execute("""
                    UPDATE users 
                    SET subscription_status = 'cancelled',
                        max_products = 0
                    WHERE id = ?
                """, (current_user.id,))

            conn.commit()
            conn.close()

            # Send cancellation email
            if email_notifier.is_configured():
                send_cancellation_email(current_user.email)

            flash('Your subscription has been cancelled. You will not be charged again.', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            conn.close()
            print(f"❌ Error cancelling subscription: {e}")
            flash('Error cancelling subscription. Please contact support.', 'error')
            return render_template('cancel_subscription.html')

    # GET request - show cancellation form
    return render_template('cancel_subscription.html')

def send_cancellation_email(email):
    """Send cancellation confirmation email"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <body>
        <h2>Subscription Cancelled</h2>
        <p>Your Screenshot Tracker subscription has been cancelled.</p>
        <p>You will not be charged again, but you can continue using the service until the end of your current billing period.</p>

        <h3>Refund Policy</h3>
        <p>If you cancelled within 7 days of your initial purchase, you may be eligible for a refund. 
        Please email support@screenshottracker.com with your account email and reason for cancellation.</p>

        <p>We're sorry to see you go! If there's anything we could have done better, please let us know.</p>
    </body>
    </html>
    """

    email_notifier.send_email(
        email,
        "Subscription Cancelled - Screenshot Tracker",
        html_content
    )

# Add route to reset rate limits (admin only)
@app.route('/admin/reset_rate_limits')
@login_required
def reset_rate_limits():
    """Reset rate limits for debugging"""
    ADMIN_EMAILS = ['amazonscreenshottracker@gmail.com', 'josh.matern@gmail.com']
    if current_user.email not in ADMIN_EMAILS:
        return "Unauthorized", 403

    try:
        limiter.reset()
        flash('Rate limits reset successfully', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        return f"Error resetting rate limits: {str(e)}", 500

# Add a route to view baseline screenshots
@app.route('/baseline_screenshot/<int:product_id>')
@login_required
def view_baseline_screenshot(product_id):
    """View the initial baseline screenshot for a product - FIXED"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Verify the product belongs to the user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT p.product_title
                FROM products p
                WHERE p.id = %s AND p.user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT p.product_title
                FROM products p
                WHERE p.id = ? AND p.user_id = ?
            ''', (product_id, current_user.id))

        product = cursor.fetchone()
        if not product:
            conn.close()
            return "Product not found", 404

        # Get the baseline screenshot
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT screenshot_data, initial_rank, initial_category, captured_at
                FROM baseline_screenshots
                WHERE product_id = %s
            ''', (product_id,))
        else:
            cursor.execute('''
                SELECT screenshot_data, initial_rank, initial_category, captured_at
                FROM baseline_screenshots
                WHERE product_id = ?
            ''', (product_id,))

        result = cursor.fetchone()
        conn.close()

        if result:
            if isinstance(result, dict):
                screenshot_data = result['screenshot_data']
                initial_rank = result['initial_rank']
                initial_category = result['initial_category']
                captured_at = result['captured_at']
            else:
                screenshot_data = result[0]
                initial_rank = result[1]
                initial_category = result[2]
                captured_at = result[3]

            print(f"📸 Found baseline screenshot for product {product_id}")
            print(f"   Data length: {len(screenshot_data) if screenshot_data else 0}")
            print(f"   Initial rank: {initial_rank}")
            print(f"   Captured at: {captured_at}")

            if screenshot_data:
                try:
                    # Handle the screenshot data
                    if isinstance(screenshot_data, str):
                        # Remove data URI prefix if present
                        if screenshot_data.startswith('data:image'):
                            screenshot_data = screenshot_data.split(',')[1]

                        # Decode base64
                        screenshot_bytes = base64.b64decode(screenshot_data)
                    else:
                        screenshot_bytes = screenshot_data

                    return send_file(
                        io.BytesIO(screenshot_bytes),
                        mimetype='image/png',
                        as_attachment=False,
                        download_name=f'baseline_product_{product_id}.png'
                    )
                except Exception as e:
                    print(f"❌ Error decoding baseline screenshot: {e}")
                    return f"Error loading screenshot: {str(e)}", 500
            else:
                print(f"⚠️ Baseline screenshot data is empty for product {product_id}")

        else:
            print(f"⚠️ No baseline screenshot found for product {product_id}")

    except Exception as e:
        print(f"❌ Error retrieving baseline screenshot: {e}")
        if conn:
            conn.close()
        return f"Error: {str(e)}", 500

    # Return a placeholder message if no baseline exists
    return """
    <div style="padding: 50px; text-align: center; background: #f5f5f5;">
        <h2>📷 No baseline screenshot available</h2>
        <p>This product may have been added before baseline screenshots were implemented.</p>
        <p><a href="/capture_baseline/""" + str(product_id) + """">Capture baseline now</a></p>
    </div>
    """, 404

@app.route('/get_achievement_count/<int:product_id>')
@login_required
def get_achievement_count(product_id):
    """Get count of achievement screenshots for a product - FIXED"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Verify product belongs to user and get achievement count
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT COUNT(bs.id)
                FROM bestseller_screenshots bs
                JOIN products p ON bs.product_id = p.id
                WHERE bs.product_id = %s AND p.user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT COUNT(bs.id)
                FROM bestseller_screenshots bs
                JOIN products p ON bs.product_id = p.id
                WHERE bs.product_id = ? AND p.user_id = ?
            ''', (product_id, current_user.id))

        result = cursor.fetchone()
        count = result[0] if result else 0

        conn.close()
        return jsonify({'count': count})

    except Exception as e:
        if conn:
            conn.close()
        return jsonify({'count': 0, 'error': str(e)})

@app.route('/latest_achievement/<int:product_id>')
@login_required
def get_latest_achievement(product_id):
    """Get the latest achievement screenshot ID for a product - FIXED"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get the most recent achievement screenshot
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT bs.id, bs.rank_achieved, bs.category, bs.achieved_at
                FROM bestseller_screenshots bs
                JOIN products p ON bs.product_id = p.id
                WHERE bs.product_id = %s AND p.user_id = %s
                ORDER BY bs.achieved_at DESC
                LIMIT 1
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT bs.id, bs.rank_achieved, bs.category, bs.achieved_at
                FROM bestseller_screenshots bs
                JOIN products p ON bs.product_id = p.id
                WHERE bs.product_id = ? AND p.user_id = ?
                ORDER BY bs.achieved_at DESC
                LIMIT 1
            ''', (product_id, current_user.id))

        result = cursor.fetchone()
        conn.close()

        if result:
            if isinstance(result, dict):
                return jsonify({
                    'screenshot_id': result['id'],
                    'rank': result['rank_achieved'],
                    'category': result['category'],
                    'achieved_at': str(result['achieved_at'])
                })
            else:
                return jsonify({
                    'screenshot_id': result[0],
                    'rank': result[1],
                    'category': result[2],
                    'achieved_at': str(result[3])
                })

        return jsonify({'screenshot_id': None})

    except Exception as e:
        if conn:
            conn.close()
        return jsonify({'screenshot_id': None, 'error': str(e)})

@app.route('/achievements/<int:product_id>')
@login_required
def view_achievements(product_id):
    """View all achievement screenshots for a product"""
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Get product info
    cursor.execute('''
        SELECT product_title, product_url
        FROM products
        WHERE id = ? AND user_id = ?
    ''', (product_id, current_user.id))

    product = cursor.fetchone()
    if not product:
        conn.close()
        flash('Product not found', 'error')
        return redirect(url_for('dashboard'))

    # Get all achievement screenshots
    cursor.execute('''
        SELECT id, rank_achieved, category, achieved_at
        FROM bestseller_screenshots
        WHERE product_id = ?
        ORDER BY achieved_at DESC
    ''', (product_id,))

    achievements = cursor.fetchall()
    conn.close()

    return render_template('achievements.html',
                         product_title=product[0],
                         product_url=product[1],
                         product_id=product_id,
                         achievements=achievements)

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard route"""
    print(f"📊 DASHBOARD: Accessed by {current_user.email} (ID: {current_user.id})")
    return dashboard_view()

def dashboard_view():
    """Dashboard view - SIMPLIFIED without API key checks"""
    try:
        if not current_user.is_authenticated:
            print("❌ DASHBOARD_VIEW: User not authenticated")
            return redirect(url_for('auth.login'))

        user_email = current_user.email
        user_id = current_user.id

        print(f"📊 DASHBOARD_VIEW: Loading for user {user_email} (ID: {user_id})")

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Get products
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    SELECT id, product_title, current_rank, current_category, 
                           is_bestseller, last_checked, created_at, active
                    FROM products 
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                ''', (user_id,))
            else:
                cursor.execute('''
                    SELECT id, product_title, current_rank, current_category, 
                           is_bestseller, last_checked, created_at, active
                    FROM products 
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                ''', (user_id,))

            products_raw = cursor.fetchall()
            print(f"📊 DASHBOARD_VIEW: Found {len(products_raw) if products_raw else 0} products")

            # Convert to list of tuples for template (expects product[0], product[1], etc.)
            products = []
            if products_raw:
                for product in products_raw:
                    if isinstance(product, dict):
                        # Convert dict to tuple in the correct order
                        products.append((
                            product['id'],
                            product['product_title'],
                            product['current_rank'],
                            product['current_category'],
                            product['is_bestseller'],
                            product['last_checked'],
                            product['created_at'],
                            product['active']
                        ))
                    else:
                        # Already a tuple, just append
                        products.append(product)

            # Get screenshots
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    SELECT bs.id, p.product_title, bs.rank_achieved, 
                           bs.category, bs.achieved_at
                    FROM bestseller_screenshots bs
                    JOIN products p ON bs.product_id = p.id
                    WHERE p.user_id = %s
                    ORDER BY bs.achieved_at DESC
                ''', (user_id,))
            else:
                cursor.execute('''
                    SELECT bs.id, p.product_title, bs.rank_achieved, 
                           bs.category, bs.achieved_at
                    FROM bestseller_screenshots bs
                    JOIN products p ON bs.product_id = p.id
                    WHERE p.user_id = ?
                    ORDER BY bs.achieved_at DESC
                ''', (user_id,))

            screenshots_raw = cursor.fetchall()

            # Convert to list of tuples for template
            screenshots = []
            if screenshots_raw:
                for screenshot in screenshots_raw:
                    if isinstance(screenshot, dict):
                        # Convert dict to tuple
                        screenshots.append((
                            screenshot['id'],
                            screenshot['product_title'],
                            screenshot['rank_achieved'],
                            screenshot['category'],
                            screenshot['achieved_at']
                        ))
                    else:
                        # Already a tuple
                        screenshots.append(screenshot)

            conn.close()

            print("✅ DASHBOARD_VIEW: Rendering dashboard template")
            print(f"   Products format: {type(products)}, Screenshots format: {type(screenshots)}")

            # Render the dashboard template with the correct data format
            return render_template('dashboard.html',
                                 email=user_email,
                                 products=products,
                                 screenshots=screenshots)

        except Exception as e:
            print(f"❌ DASHBOARD_VIEW: Database error: {e}")
            import traceback
            traceback.print_exc()
            if conn:
                conn.close()

            # Return an error page instead of raising
            return f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h1>Dashboard Error</h1>
                <p>Unable to load dashboard data.</p>
                <p>Error: {str(e)}</p>
                <br>
                <a href="/emergency_dashboard">Emergency Dashboard</a> | 
                <a href="/auth/logout">Logout</a>
            </body>
            </html>
            """, 500

    except Exception as e:
        print(f"❌ DASHBOARD_VIEW: Fatal error: {e}")
        import traceback
        traceback.print_exc()

        # Return error page instead of redirecting
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h1>Dashboard Error</h1>
            <p>A critical error occurred.</p>
            <p>Error: {str(e)}</p>
            <br>
            <a href="/auth/logout">Logout and try again</a>
        </body>
        </html>
        """, 500

@app.route('/test_dashboard')
@login_required
def test_dashboard():
    """Test route to debug dashboard issues"""
    try:
        return f"""
        <html>
        <body>
            <h2>Dashboard Debug Info</h2>
            <p><strong>Authenticated:</strong> {current_user.is_authenticated}</p>
            <p><strong>User ID:</strong> {current_user.id}</p>
            <p><strong>User Email:</strong> {current_user.email}</p>
            <p><strong>User Name:</strong> {current_user.full_name}</p>
            <br>
            <p><a href="/dashboard">Try Dashboard</a></p>
            <p><a href="/">Go Home</a></p>
            <p><a href="/auth/logout">Logout</a></p>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/clear_session')
def clear_session():
    """Clear session to fix redirect loops"""
    session.clear()
    flash('Session cleared. Please log in again.', 'info')
    return redirect(url_for('auth.login'))

@app.route('/emergency_dashboard')
@login_required
def emergency_dashboard():
    """Emergency dashboard that doesn't use database or templates"""
    return f"""
    <html>
    <head>
        <title>Emergency Dashboard</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                padding: 20px;
                max-width: 800px;
                margin: 0 auto;
            }}
            .card {{
                background: #f5f5f5;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
            }}
        </style>
    </head>
    <body>
        <h1>Emergency Dashboard</h1>

        <div class="card">
            <h2>User Info</h2>
            <p><strong>Email:</strong> {current_user.email}</p>
            <p><strong>ID:</strong> {current_user.id}</p>
            <p><strong>Authenticated:</strong> {current_user.is_authenticated}</p>
        </div>

        <div class="card">
            <h2>Quick Actions</h2>
            <ul>
                <li><a href="/test_dashboard">Test Dashboard</a></li>
                <li><a href="/add_product_form">Add Product</a></li>
                <li><a href="/settings">Settings</a></li>
                <li><a href="/check_api_key">Check API Key</a></li>
                <li><a href="/check_scrapingbee_usage">Check ScrapingBee Usage</a></li>
                <li><a href="/auth/logout">Logout</a></li>
                <li><a href="/clear_session">Clear Session (if stuck)</a></li>
            </ul>
        </div>

        <div class="card">
            <h2>Debug</h2>
            <p>If you're seeing this, the main dashboard has an error.</p>
            <p>Try <a href="/clear_session">clearing your session</a> and logging in again.</p>
        </div>
    </body>
    </html>
    """

@app.route('/check_api_key')
@login_required
def check_api_key():
    """Debug route to check API key status"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        if get_db_type() == 'postgresql':
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (current_user.id,))
        else:
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (current_user.id,))

        result = cursor.fetchone()

        if result:
            if isinstance(result, dict):
                api_key = result.get('scrapingbee_api_key')
            else:
                api_key = result[0] if result else None
        else:
            api_key = None

        conn.close()

        return f"""
        <html>
        <body style="font-family: monospace; padding: 20px;">
            <h2>API Key Status</h2>
            <p><strong>User ID:</strong> {current_user.id}</p>
            <p><strong>Email:</strong> {current_user.email}</p>
            <p><strong>API Key Exists:</strong> {bool(api_key)}</p>
            <p><strong>API Key Length:</strong> {len(api_key) if api_key else 0}</p>
            <p><strong>API Key Preview:</strong> {api_key[:10] + '...' if api_key else 'None'}</p>
            <p><strong>Result Type:</strong> {type(result).__name__}</p>
            <p><strong>Result Value:</strong> {result}</p>
            <br>
            <a href="/settings">Go to Settings</a> | 
            <a href="/dashboard">Back to Dashboard</a>
        </body>
        </html>
        """
    except Exception as e:
        conn.close()
        return f"Error: {str(e)}", 500

@app.route('/debug_session')
@login_required
def debug_session():
    """Debug session and authentication state"""
    import json

    session_data = {
        'authenticated': current_user.is_authenticated,
        'user_id': current_user.id if current_user.is_authenticated else None,
        'user_email': current_user.email if current_user.is_authenticated else None,
        'session_keys': list(session.keys()),
        'session_permanent': session.permanent if hasattr(session, 'permanent') else None
    }

    return f"""
    <html>
    <body style="font-family: monospace; padding: 20px;">
        <h2>Session Debug</h2>
        <pre>{json.dumps(session_data, indent=2, default=str)}</pre>
        <br>
        <h3>Quick Links:</h3>
        <ul>
            <li><a href="/dashboard">Dashboard</a></li>
            <li><a href="/test_dashboard">Test Dashboard</a></li>
            <li><a href="/">Home</a></li>
            <li><a href="/auth/logout">Logout</a></li>
            <li><a href="/auth/login">Login</a></li>
        </ul>
    </body>
    </html>
    """

@app.route('/debug/all_screenshots')
@login_required
def debug_all_screenshots():
    """Show all screenshots in the database for current user"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get all baseline screenshots
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT b.id, b.product_id, p.product_title, 
                       LENGTH(b.screenshot_data) as size, b.captured_at
                FROM baseline_screenshots b
                JOIN products p ON b.product_id = p.id
                WHERE p.user_id = %s
                ORDER BY b.captured_at DESC
            ''', (current_user.id,))
        else:
            cursor.execute('''
                SELECT b.id, b.product_id, p.product_title, 
                       LENGTH(b.screenshot_data) as size, b.captured_at
                FROM baseline_screenshots b
                JOIN products p ON b.product_id = p.id
                WHERE p.user_id = ?
                ORDER BY b.captured_at DESC
            ''', (current_user.id,))

        baselines = cursor.fetchall()

        # Get all achievement screenshots
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT bs.id, bs.product_id, p.product_title, 
                       LENGTH(bs.screenshot_data) as size, bs.achieved_at,
                       bs.rank_achieved, bs.category
                FROM bestseller_screenshots bs
                JOIN products p ON bs.product_id = p.id
                WHERE p.user_id = %s
                ORDER BY bs.achieved_at DESC
            ''', (current_user.id,))
        else:
            cursor.execute('''
                SELECT bs.id, bs.product_id, p.product_title, 
                       LENGTH(bs.screenshot_data) as size, bs.achieved_at,
                       bs.rank_achieved, bs.category
                FROM bestseller_screenshots bs
                JOIN products p ON bs.product_id = p.id
                WHERE p.user_id = ?
                ORDER BY bs.achieved_at DESC
            ''', (current_user.id,))

        achievements = cursor.fetchall()

        conn.close()

        html = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                table { border-collapse: collapse; width: 100%; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background: #f5f5f5; }
                .success { color: green; }
                .warning { color: orange; }
            </style>
        </head>
        <body>
            <h1>All Screenshots Debug</h1>

            <h2>Baseline Screenshots</h2>
        """

        if baselines:
            html += """
            <table>
                <tr>
                    <th>ID</th>
                    <th>Product ID</th>
                    <th>Product</th>
                    <th>Size</th>
                    <th>Captured</th>
                    <th>Actions</th>
                </tr>
            """

            for baseline in baselines:
                if isinstance(baseline, dict):
                    b_id = baseline['id']
                    p_id = baseline['product_id']
                    title = baseline['product_title']
                    size = baseline['size']
                    captured = baseline['captured_at']
                else:
                    b_id = baseline[0]
                    p_id = baseline[1]
                    title = baseline[2]
                    size = baseline[3]
                    captured = baseline[4]

                html += f"""
                <tr>
                    <td>{b_id}</td>
                    <td>{p_id}</td>
                    <td>{title[:30]}...</td>
                    <td>{size} bytes</td>
                    <td>{captured}</td>
                    <td><a href="/baseline_screenshot/{p_id}" target="_blank">View</a></td>
                </tr>
                """

            html += "</table>"
        else:
            html += "<p class='warning'>No baseline screenshots found</p>"

        html += "<h2>Achievement Screenshots</h2>"

        if achievements:
            html += """
            <table>
                <tr>
                    <th>ID</th>
                    <th>Product ID</th>
                    <th>Product</th>
                    <th>Size</th>
                    <th>Rank</th>
                    <th>Category</th>
                    <th>Achieved</th>
                    <th>Actions</th>
                </tr>
            """

            for achievement in achievements:
                if isinstance(achievement, dict):
                    a_id = achievement['id']
                    p_id = achievement['product_id']
                    title = achievement['product_title']
                    size = achievement['size']
                    achieved = achievement['achieved_at']
                    rank = achievement['rank_achieved']
                    category = achievement['category']
                else:
                    a_id = achievement[0]
                    p_id = achievement[1]
                    title = achievement[2]
                    size = achievement[3]
                    achieved = achievement[4]
                    rank = achievement[5]
                    category = achievement[6]

                html += f"""
                <tr>
                    <td>{a_id}</td>
                    <td>{p_id}</td>
                    <td>{title[:30]}...</td>
                    <td>{size} bytes</td>
                    <td>{rank}</td>
                    <td>{category[:30] if category else 'N/A'}...</td>
                    <td>{achieved}</td>
                    <td>
                        <a href="/screenshot/{a_id}" target="_blank">View</a> |
                        <a href="/fix_baseline/{p_id}">Use as Baseline</a>
                    </td>
                </tr>
                """

            html += "</table>"
        else:
            html += "<p class='warning'>No achievement screenshots found</p>"

        html += """
            <br>
            <a href="/dashboard">Back to Dashboard</a>
        </body>
        </html>
        """

        return html

    except Exception as e:
        if conn:
            conn.close()
        import traceback
        return f"<pre>{traceback.format_exc()}</pre>", 500

# Settings page route
@app.route('/settings')
@login_required
def settings():
    """Simple account settings page"""
    return render_template('account_settings.html', user=current_user)

@app.route('/terms')
def terms():
    """Terms of Service page"""
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    """Privacy Policy page"""
    return render_template('privacy.html')

@app.route('/refunds')
def refunds():
    """Refund Policy page"""
    return render_template('refunds.html')

@app.route('/test_encryption')
@login_required
def test_encryption():
    """Test the encryption/decryption system"""
    test_key = "TEST_API_KEY_1234567890"

    try:
        # Test encryption
        encrypted = api_encryption.encrypt(test_key)
        if encrypted is not None:
            encrypted_preview = encrypted[:50] + '...'
        else:
            encrypted_preview = '(Encryption failed, value is None)'

        # Test decryption
        decrypted = api_encryption.decrypt(encrypted)

        # Test database save and retrieve
        conn = get_db()
        cursor = conn.cursor()

        # Save encrypted key
        if get_db_type() == 'postgresql':
            cursor.execute('''
                UPDATE users 
                SET scrapingbee_api_key = %s 
                WHERE id = %s
            ''', (encrypted, current_user.id))
        else:
            cursor.execute('''
                UPDATE users 
                SET scrapingbee_api_key = ? 
                WHERE id = ?
            ''', (encrypted, current_user.id))

        conn.commit()

        # Retrieve it back
        if get_db_type() == 'postgresql':
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (current_user.id,))
        else:
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (current_user.id,))

        result = cursor.fetchone()

        if result:
            if isinstance(result, dict):
                retrieved = result.get('scrapingbee_api_key')
            else:
                retrieved = result[0] if result else None
        else:
            retrieved = None

        # Try to decrypt retrieved value
        if retrieved:
            try:
                decrypted_from_db = api_encryption.decrypt(retrieved)
            except Exception as e:
                decrypted_from_db = f"Decryption failed: {str(e)}"
        else:
            decrypted_from_db = "No value retrieved from database"

        conn.close()

        return f"""
        <html>
        <body style="font-family: monospace; padding: 20px;">
            <h2>Encryption System Test</h2>

            <h3>1. Basic Encryption Test</h3>
            <p><strong>Original:</strong> {test_key}</p>
            <p><strong>Encrypted:</strong> {encrypted_preview}</p>
            <p><strong>Encrypted Length:</strong> {len(encrypted_preview)}</p>
            <p><strong>Decrypted:</strong> {decrypted}</p>
            <p><strong>Match:</strong> {decrypted == test_key}</p>

            <h3>2. Database Save/Retrieve Test</h3>
            <p><strong>Saved to DB:</strong> {encrypted_preview}</p>
            <p><strong>Retrieved from DB:</strong> {retrieved[:50] + '...' if retrieved else 'None'}</p>
            <p><strong>Retrieved Length:</strong> {len(retrieved) if retrieved else 0}</p>
            <p><strong>Values Match:</strong> {retrieved == encrypted if retrieved else False}</p>

            <h3>3. Full Cycle Test</h3>
            <p><strong>Decrypted from DB:</strong> {decrypted_from_db}</p>
            <p><strong>Final Match:</strong> {decrypted_from_db == test_key}</p>

            <br>
            <a href="/check_api_key">Check API Key</a> | 
            <a href="/settings">Go to Settings</a> | 
            <a href="/clear_api_key">Clear API Key</a>
        </body>
        </html>
        """

    except Exception as e:
        import traceback
        return f"""
        <html>
        <body style="font-family: monospace; padding: 20px;">
            <h2>Encryption Test Failed</h2>
            <pre>{traceback.format_exc()}</pre>
        </body>
        </html>
        """, 500

@app.route('/force_start_scheduler')
@login_required
def force_start_scheduler():
    """Force start the scheduler"""
    if current_user.email not in ['amazonscreenshottracker@gmail.com', 'josh.matern@gmail.com']:
        return "Unauthorized", 403

    global scheduler_thread, scheduler_running, scheduler_initialized

    # Reset state
    scheduler_initialized = False
    scheduler_running = False

    # Try to start
    success = ensure_scheduler_running()

    if success:
        return """
        <h2>✅ Scheduler Started!</h2>
        <p>The scheduler should now be running.</p>
        <ul>
            <li><a href="/credit_leak_detector">Check Status</a></li>
            <li><a href="/scheduler_status">Scheduler Status JSON</a></li>
            <li><a href="/dashboard">Dashboard</a></li>
        </ul>
        """
    else:
        return """
        <h2>❌ Failed to Start Scheduler</h2>
        <p>Check the logs for errors.</p>
        <a href="/dashboard">Dashboard</a>
        """

@app.route('/screenshot/<int:screenshot_id>')
def view_screenshot(screenshot_id):
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT screenshot_data FROM bestseller_screenshots WHERE id = ?
    ''', (screenshot_id,))

    result = cursor.fetchone()
    conn.close()

    if result and result[0]:
        try:
            # The screenshot data from json_response is already base64
            # but we need to ensure it's properly decoded
            screenshot_data = result[0]

            # If it's a string that looks like base64, decode it
            if isinstance(screenshot_data, str):
                # Remove any potential data URI prefix
                if screenshot_data.startswith('data:image'):
                    screenshot_data = screenshot_data.split(',')[1]

                screenshot_bytes = base64.b64decode(screenshot_data)
            else:
                screenshot_bytes = screenshot_data

            return send_file(
                io.BytesIO(screenshot_bytes),
                mimetype='image/png',
                as_attachment=False
            )
        except Exception as e:
            print(f"❌ Error decoding screenshot: {e}")
            return f"Error loading screenshot: {str(e)}", 500

    return "Screenshot not found", 404

@app.route('/add_target_category', methods=['POST'])
@login_required
def add_target_category():
    
    conn = get_db()
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        category_name = data.get('category_name')
        target_rank = data.get('target_rank', 1)

        # Remove email check - use authenticated user instead
        if not all([product_id, category_name]):
            return jsonify({'error': 'Missing required fields'}), 400

        
        cursor = conn.cursor()

        # Verify product belongs to current authenticated user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT id FROM products 
                WHERE id = %s AND user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT id FROM products 
                WHERE id = ? AND user_id = ?
            ''', (product_id, current_user.id))

        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Product not found or unauthorized'}), 404

        # Add target category
        if get_db_type() == 'postgresql':
            cursor.execute('''
                INSERT INTO target_categories 
                (product_id, category_name, target_rank, created_at)
                VALUES (%s, %s, %s, %s)
            ''', (product_id, category_name, target_rank, datetime.now()))
        else:
            cursor.execute('''
                INSERT INTO target_categories 
                (product_id, category_name, target_rank, created_at)
                VALUES (?, ?, ?, ?)
            ''', (product_id, category_name, target_rank, datetime.now()))

        conn.commit()
        conn.close()

        return jsonify({'status': 'Target category added successfully'})

    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        print(f"Error adding target category: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_target_categories/<int:product_id>')
@login_required  # Add authentication
def get_target_categories(product_id):
    """Get all target categories for a product - FIXED"""
    # Remove email parameter - use authenticated user
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Verify ownership and get categories
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT tc.id, tc.category_name, tc.target_rank, tc.best_rank_achieved, 
                       tc.is_achieved, tc.date_achieved
                FROM target_categories tc
                JOIN products p ON tc.product_id = p.id
                WHERE tc.product_id = %s AND p.user_id = %s
                ORDER BY tc.created_at DESC
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT tc.id, tc.category_name, tc.target_rank, tc.best_rank_achieved, 
                       tc.is_achieved, tc.date_achieved
                FROM target_categories tc
                JOIN products p ON tc.product_id = p.id
                WHERE tc.product_id = ? AND p.user_id = ?
                ORDER BY tc.created_at DESC
            ''', (product_id, current_user.id))

        categories = []
        for row in cursor.fetchall():
            if isinstance(row, dict):
                categories.append({
                    'id': row['id'],
                    'category_name': row['category_name'],
                    'target_rank': row['target_rank'],
                    'best_rank_achieved': row['best_rank_achieved'],
                    'is_achieved': bool(row['is_achieved']),
                    'date_achieved': str(row['date_achieved']) if row['date_achieved'] else None
                })
            else:
                categories.append({
                    'id': row[0],
                    'category_name': row[1],
                    'target_rank': row[2],
                    'best_rank_achieved': row[3],
                    'is_achieved': bool(row[4]),
                    'date_achieved': str(row[5]) if row[5] else None
                })

        conn.close()
        return jsonify(categories)

    except Exception as e:
        if conn:
            conn.close()
        print(f"Error getting target categories: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/check_products', methods=['POST'])
@login_required
@limiter.limit("30 per hour")  # Reasonable limit for manual checks
def check_products():
    """Manual check for user's selected products"""
    return jsonify({
        'error': 'Bulk checking has been replaced with automatic hourly monitoring. Products are checked automatically every 60 minutes.'
    }), 400

@app.route('/send_feedback', methods=['POST'])
@login_required
def send_feedback():
    """Handle beta feedback submission"""
    try:
        # Get form data
        rating = request.form.get('rating')
        love = request.form.get('love', '')
        improve = request.form.get('improve', '')
        bugs = request.form.get('bugs', '')
        would_pay = request.form.get('would_pay')
        price_point = request.form.get('price_point', 'N/A')

        # Save to database for tracking
        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        # Create feedback table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_email TEXT,
                rating INTEGER,
                love TEXT,
                improve TEXT,
                bugs TEXT,
                would_pay TEXT,
                price_point TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Insert feedback
        cursor.execute('''
            INSERT INTO feedback 
            (user_id, user_email, rating, love, improve, bugs, would_pay, price_point)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            current_user.id,
            current_user.email,
            int(rating) if rating else None,
            love,
            improve,
            bugs,
            would_pay,
            price_point
        ))

        conn.commit()
        conn.close()

        # Send email notification to admin
        if email_notifier.is_configured():
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>🎯 New Beta Feedback Received!</h2>

                <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <p><strong>From:</strong> {current_user.email}</p>
                    <p><strong>Rating:</strong> {rating}/10</p>
                    <p><strong>Would Pay:</strong> {would_pay}</p>
                    <p><strong>Price Point:</strong> ${price_point}/month</p>
                </div>

                <div style="margin: 20px 0;">
                    <h3>What they love:</h3>
                    <p style="background: #e8f5e9; padding: 15px; border-radius: 5px;">
                        {love or 'No response'}
                    </p>
                </div>

                <div style="margin: 20px 0;">
                    <h3>What could be improved:</h3>
                    <p style="background: #fff3e0; padding: 15px; border-radius: 5px;">
                        {improve or 'No response'}
                    </p>
                </div>

                <div style="margin: 20px 0;">
                    <h3>Bugs reported:</h3>
                    <p style="background: #ffebee; padding: 15px; border-radius: 5px;">
                        {bugs or 'No bugs reported'}
                    </p>
                </div>

                <hr>
                <p style="color: #666; font-size: 12px;">
                    Feedback submitted at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </body>
            </html>
            """

            # Send to admin email
            email_notifier.send_email(
                'amazonscreenshottracker@gmail.com',  # Send to yourself
                f'[Beta Feedback] Rating: {rating}/10 from {current_user.email}',
                html_content
            )

        flash('Thank you for your feedback! It helps us improve.', 'success')

    except Exception as e:
        print(f"Error saving feedback: {e}")
        import traceback
        traceback.print_exc()
        flash('Error submitting feedback. Please try again.', 'error')

    return redirect(url_for('dashboard'))

@app.route('/deployment-test')
def deployment_test():
    """Simple test to verify deployment is working"""
    return jsonify({
        'status': 'ok',
        'message': 'App is deployed and running',
        'timestamp': datetime.now().isoformat(),
        'scheduler_enabled': os.environ.get('ENABLE_SCHEDULER', 'false')
    })

@app.route('/toggle_monitoring/<int:product_id>')
@login_required
def toggle_monitoring(product_id):
    """Toggle product monitoring on/off - FIXED"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get current status - use authenticated user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT active FROM products 
                WHERE id = %s AND user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT active FROM products 
                WHERE id = ? AND user_id = ?
            ''', (product_id, current_user.id))

        result = cursor.fetchone()
        if not result:
            conn.close()
            return jsonify({'error': 'Product not found or unauthorized'}), 404

        current_status = result['active'] if isinstance(result, dict) else result[0]
        new_status = not current_status

        # Update status
        if get_db_type() == 'postgresql':
            cursor.execute('''
                UPDATE products SET active = %s WHERE id = %s AND user_id = %s
            ''', (new_status, product_id, current_user.id))
        else:
            cursor.execute('''
                UPDATE products SET active = ? WHERE id = ? AND user_id = ?
            ''', (new_status, product_id, current_user.id))

        conn.commit()
        conn.close()

        status_text = "resumed" if new_status else "paused"
        return jsonify({'status': f'Product monitoring {status_text}'})

    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        print(f"Error toggling monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    conn = get_db()
    try:
        cursor = conn.cursor()

        # Verify ownership using authenticated user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT id FROM products 
                WHERE id = %s AND user_id = %s
            ''', (product_id, current_user.id))
        else:
            cursor.execute('''
                SELECT id FROM products 
                WHERE id = ? AND user_id = ?
            ''', (product_id, current_user.id))

        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Product not found or unauthorized'}), 404

        # Delete related records
        if get_db_type() == 'postgresql':
            cursor.execute('DELETE FROM target_categories WHERE product_id = %s', (product_id,))
            cursor.execute('DELETE FROM bestseller_screenshots WHERE product_id = %s', (product_id,))
            cursor.execute('DELETE FROM baseline_screenshots WHERE product_id = %s', (product_id,))
            cursor.execute('DELETE FROM rankings WHERE product_id = %s', (product_id,))
            cursor.execute('DELETE FROM products WHERE id = %s AND user_id = %s', (product_id, current_user.id))
        else:
            cursor.execute('DELETE FROM target_categories WHERE product_id = ?', (product_id,))
            cursor.execute('DELETE FROM bestseller_screenshots WHERE product_id = ?', (product_id,))
            cursor.execute('DELETE FROM baseline_screenshots WHERE product_id = ?', (product_id,))
            cursor.execute('DELETE FROM rankings WHERE product_id = ?', (product_id,))
            cursor.execute('DELETE FROM products WHERE id = ? AND user_id = ?', (product_id, current_user.id))

        conn.commit()
        conn.close()

        return jsonify({'status': 'Product deleted successfully'})

    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        print(f"Error deleting product: {e}")
        return jsonify({'error': str(e)}), 500

def check_user_products(user_id, limit=10):
    """Check products for a specific user with credit limits"""
    print(f"🔄 Checking products for user {user_id}")

    conn = get_db()
    cursor = conn.cursor()

    products_checked = 0
    credits_used = 0
    achievements = []

    try:
        # Get user's active products
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT p.id, p.product_url, p.product_title, p.current_rank, 
                       p.current_category, p.is_bestseller,
                       u.scrapingbee_api_key
                FROM products p
                JOIN users u ON p.user_id = u.id
                WHERE p.user_id = %s 
                  AND p.active = true
                  AND u.scrapingbee_api_key IS NOT NULL
                ORDER BY p.last_checked ASC NULLS FIRST
                LIMIT %s
            ''', (user_id, limit))
        else:
            cursor.execute('''
                SELECT p.id, p.product_url, p.product_title, p.current_rank,
                       p.current_category, p.is_bestseller,
                       u.scrapingbee_api_key
                FROM products p
                JOIN users u ON p.user_id = u.id
                WHERE p.user_id = ? 
                  AND p.active = 1
                  AND u.scrapingbee_api_key IS NOT NULL
                ORDER BY p.last_checked ASC
                LIMIT ?
            ''', (user_id, limit))

        products = cursor.fetchall()

        if not products:
            conn.close()
            return {
                'products_checked': 0,
                'credits_used': 0,
                'achievements': [],
                'message': 'No active products to check'
            }

        # Create monitor for user
        user_monitor = AmazonMonitor.for_user(user_id)

        if not user_monitor.api_key:
            conn.close()
            return {
                'products_checked': 0,
                'credits_used': 0,
                'achievements': [],
                'message': 'No API key configured'
            }

        for product_row in products:
            product_id = None
            try:
                # Extract product data
                if isinstance(product_row, dict):
                    product_id = product_row['id']
                    url = product_row['product_url']
                    title = product_row['product_title']
                    previous_rank = int(product_row['current_rank']) if product_row['current_rank'] else 999999
                    was_bestseller = product_row['is_bestseller']
                else:
                    product_id = product_row[0]
                    url = product_row[1]
                    title = product_row[2]
                    previous_rank = int(product_row[3]) if product_row[3] else 999999
                    was_bestseller = product_row[5]

                print(f"🔍 Checking: {title[:50]}...")

                # Scrape the product
                result = user_monitor.scrape_amazon_page(url)
                credits_used += 1

                if result.get('success'):
                    product_info = user_monitor.extract_product_info(result.get('html', ''))

                    current_rank = int(product_info['rank']) if product_info.get('rank') else None
                    is_bestseller_now = product_info.get('is_bestseller', False)

                    # Update product info
                    if get_db_type() == 'postgresql':
                        cursor.execute('''
                            UPDATE products 
                            SET current_rank = %s, current_category = %s, 
                                is_bestseller = %s, last_checked = %s
                            WHERE id = %s
                        ''', (
                            product_info.get('rank'),
                            product_info.get('category'),
                            is_bestseller_now,
                            datetime.now(),
                            product_id
                        ))
                    else:
                        cursor.execute('''
                            UPDATE products 
                            SET current_rank = ?, current_category = ?, 
                                is_bestseller = ?, last_checked = ?
                            WHERE id = ?
                        ''', (
                            product_info.get('rank'),
                            product_info.get('category'),
                            is_bestseller_now,
                            datetime.now(),
                            product_id
                        ))

                    # Record ranking history
                    if get_db_type() == 'postgresql':
                        cursor.execute('''
                            INSERT INTO rankings 
                            (product_id, rank_number, category, is_bestseller, checked_at)
                            VALUES (%s, %s, %s, %s, %s)
                        ''', (
                            product_id, current_rank,
                            product_info.get('category'),
                            is_bestseller_now,
                            datetime.now()
                        ))
                    else:
                        cursor.execute('''
                            INSERT INTO rankings 
                            (product_id, rank_number, category, is_bestseller, checked_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            product_id, current_rank,
                            product_info.get('category'),
                            is_bestseller_now,
                            datetime.now()
                        ))

                    # Check for achievements
                    achievement_triggered = False
                    achievement_reason = ""

                    if is_bestseller_now and not was_bestseller:
                        achievement_triggered = True
                        achievement_reason = "New Bestseller!"
                    elif current_rank:
                        if current_rank <= 10 and previous_rank > 10:
                            achievement_triggered = True
                            achievement_reason = f"Entered Top 10! (#{current_rank})"
                        elif current_rank == 1 and previous_rank != 1:
                            achievement_triggered = True
                            achievement_reason = "Reached #1!"

                    # Save screenshot if achievement
                    if achievement_triggered and result.get('screenshot'):
                        print(f"🏆 Achievement detected: {achievement_reason}")

                        if get_db_type() == 'postgresql':
                            cursor.execute('''
                                INSERT INTO bestseller_screenshots 
                                (product_id, screenshot_data, rank_achieved, category, achieved_at)
                                VALUES (%s, %s, %s, %s, %s)
                            ''', (
                                product_id,
                                result['screenshot'],
                                product_info.get('rank'),
                                f"{product_info.get('category', '')} - {achievement_reason}",
                                datetime.now()
                            ))
                        else:
                            cursor.execute('''
                                INSERT INTO bestseller_screenshots 
                                (product_id, screenshot_data, rank_achieved, category, achieved_at)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (
                                product_id,
                                result['screenshot'],
                                product_info.get('rank'),
                                f"{product_info.get('category', '')} - {achievement_reason}",
                                datetime.now()
                            ))

                        achievements.append({
                            'product': title,
                            'achievement': achievement_reason,
                            'rank': current_rank
                        })

                        # Send email notification
                        if get_db_type() == 'postgresql':
                            cursor.execute('SELECT email FROM users WHERE id = %s', (user_id,))
                        else:
                            cursor.execute('SELECT email FROM users WHERE id = ?', (user_id,))

                        user_email_row = cursor.fetchone()
                        if user_email_row:
                            user_email = user_email_row['email'] if isinstance(user_email_row, dict) else user_email_row[0]
                        else:
                            print(f"📧 Failed to send email. User email not found for user_id: {user_id}")
                            continue  # Skip sending emails as user email is not available

                        if email_notifier.is_configured():
                            product_info['achievement_reason'] = achievement_reason
                            email_notifier.send_bestseller_notification(
                                user_email,
                                product_info,
                                result['screenshot'],
                                achievement_type=achievement_reason
                            )

                    products_checked += 1
                    conn.commit()

                    # Rate limiting between products
                    if products_checked < len(products):
                        time.sleep(1)  # 1 second delay between products

                else:
                    print(f"❌ Failed to scrape: {result.get('error', 'Unknown error')}")

            except Exception as e:
                print(f"❌ Error checking product {product_id}: {e}")
                continue

        conn.close()

        return {
            'products_checked': products_checked,
            'credits_used': credits_used,
            'achievements': achievements,
            'message': f'Successfully checked {products_checked} products'
        }

    except Exception as e:
        print(f"❌ Error in check_user_products: {e}")
        if conn:
            conn.close()
        raise

@app.route('/create_checkout', methods=['POST'])
@limiter.limit("5 per hour per ip")
def create_checkout():
    data = request.get_json()
    price_id = data.get('price_id')

    try:
        # Build session parameters
        session_params = {
            'payment_method_types': ['card'],
            'line_items': [{'price': price_id, 'quantity': 1}],
            'mode': 'subscription',
            'success_url': 'https://screenshottracker.com/success?session_id={CHECKOUT_SESSION_ID}',
            'cancel_url': 'https://screenshottracker.com/pricing',
             "allow_promotion_codes": True
        }

        # Only add email if user is logged in
        if current_user.is_authenticated:
            session_params['customer_email'] = current_user.email

        session = stripe.checkout.Session.create(**session_params)
        return jsonify({'url': session.url})
    except Exception as e:
        print(f"Stripe error: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/stripe_webhook', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    """Handle Stripe subscription events"""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')

    # Validate required parameters
    if not sig_header:
        return 'Missing Stripe-Signature header', 400
    if not webhook_secret:
        return 'Webhook secret not configured', 400

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        return 'Invalid payload', 400
    except Exception as e:
        if 'SignatureVerificationError' in str(type(e)):
            return 'Invalid signature', 400
        else:
            return 'Webhook error', 400

    conn = get_db()
    cursor = conn.cursor()

    print("🔧 DATABASE CONNECTION TEST")
    print(f"   Connection object: {conn}")
    print(f"   Cursor object: {cursor}")

    # Try a simple query
    try:
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        print(f"   Test query result: {result}")
    except Exception as e:
        print(f"   Test query failed: {e}")

    try:
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            email = (
                session.get('customer_email')
                or session.get('customer_details', {}).get('email')
            )
            subscription_id = session.get('subscription')
            customer_id = session.get('customer')

            if not email or not subscription_id:
                print("⚠️ Missing email or subscription ID")
                return '', 200

            print("🔔 Received checkout.session.completed event:")
            print(f"   Email: {email}")
            print(f"   Subscription ID: {subscription_id}")
            print(f"   Customer ID: {customer_id}")

            # Get subscription details with CORRECT path to price_id
            price_id = None
            # Get subscription details
            try:
                subscription = stripe.Subscription.retrieve(subscription_id)
                price_id = subscription['items']['data'][0]['price']['id']
                print(f"✅ Retrieved subscription. Price ID: {price_id}")
            except Exception as e:
                print(f"⚠️ Error retrieving subscription details: {e}")

            # Map price IDs to tiers
            tier_map = {
                os.environ.get('STRIPE_AUTHOR_WEEKLY_PRICE'): ('author', 2),
                os.environ.get('STRIPE_AUTHOR_MONTHLY_PRICE'): ('author', 2),
                os.environ.get('STRIPE_AUTHOR_YEARLY_PRICE'): ('author', 2),
                os.environ.get('STRIPE_PUBLISHER_WEEKLY_PRICE'): ('publisher', 5),
                os.environ.get('STRIPE_PUBLISHER_MONTHLY_PRICE'): ('publisher', 5),
                os.environ.get('STRIPE_PUBLISHER_YEARLY_PRICE'): ('publisher', 5),
            }

            tier, max_products = tier_map.get(price_id, ('author', 2))
            print(f"📊 Mapped to tier: {tier}, max_products: {max_products}")

            # Generate setup token
            setup_token = secrets.token_urlsafe(32)
            subscription_expires = datetime.now() + timedelta(days=30)
            setup_token_expiry = datetime.now() + timedelta(hours=24)

            print(f"🔑 Generated setup token: {setup_token[:10]}...")

            # CREATE USER IN DATABASE
            try:
                print(f"🔧 Database type: {get_db_type()}")
                print(f"🔧 About to insert user with email: {email}")
                
                if get_db_type() == 'postgresql':
                    print(f"🔧 Using PostgreSQL path")
                    print(f"🔧 Values to insert:")
                    print(f"   - email: {email}")
                    print(f"   - subscription_status: active")
                    print(f"   - subscription_tier: {tier}")
                    print(f"   - stripe_subscription_id: {subscription_id}")
                    print(f"   - stripe_customer_id: {customer_id}")
                    print(f"   - max_products: {max_products}")
                    print(f"   - setup_token length: {len(setup_token)}")
                    cursor.execute("""
                        INSERT INTO users (
                            email, 
                            password_hash,
                            subscription_status,
                            subscription_tier,
                            stripe_subscription_id,
                            stripe_customer_id,
                            max_products,
                            is_verified,
                            subscription_expires,
                            setup_token,
                            setup_token_expiry
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (email) DO UPDATE SET
                            subscription_tier = EXCLUDED.subscription_tier,
                            subscription_status = EXCLUDED.subscription_status,
                            stripe_subscription_id = EXCLUDED.stripe_subscription_id,
                            stripe_customer_id = EXCLUDED.stripe_customer_id,
                            max_products = EXCLUDED.max_products,
                            setup_token = EXCLUDED.setup_token,
                            setup_token_expiry = EXCLUDED.setup_token_expiry
                    """, (
                        email,
                        'PENDING_SETUP',
                        'active',
                        tier,
                        subscription_id,
                        customer_id,
                        max_products,
                        False,
                        subscription_expires,
                        setup_token,
                        setup_token_expiry
                    ))

                    print(f"🔧 Execute completed, rowcount: {cursor.rowcount}")
                    conn.commit()
                    print("🔧 Commit completed")
                    print(f"✅ User created/updated in database for {email}")

                    # Verify the token was saved
                    print("🔧 Querying to verify user was saved...")
                    cursor.execute("SELECT setup_token, subscription_tier, max_products FROM users WHERE email = %s", (email,))
                    row = cursor.fetchone()
                    if row:
                        print(f"💡 Verified in DB - Email: {row[0]}")
                        print(f"   Setup token: {row[1][:10] if row[1] else 'NULL'}...")
                        print(f"   Tier: {row[2]}, Max products: {row[3]}")
                        print(f"   Status: {row[4]}")
                    else:
                        print(f"⚠️ CRITICAL: No user found in DB after insert for {email}")
                        print("🔧 Checking if ANY users exist in database...")
                        cursor.execute("SELECT COUNT(*) FROM users")
                        count = cursor.fetchone()
                        print(f"   Total users in database: {count[0] if count else 'ERROR'}")
                        return '', 500

                else:  # SQLite
                    print("🔧 Using SQLite path")
                    cursor.execute("""
                        INSERT OR REPLACE INTO users (
                            email,
                            stripe_customer_id,
                            stripe_subscription_id,
                            password_hash,
                            is_verified,
                            subscription_status,
                            subscription_tier,
                            max_products,
                            subscription_expires,
                            setup_token,
                            setup_token_expiry
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        email,
                        customer_id,
                        subscription_id,
                        'PENDING_SETUP',
                        0,
                        'active',
                        tier,
                        max_products,
                        subscription_expires,
                        setup_token,
                        setup_token_expiry
                    ))

                    conn.commit()
                    print(f"✅ User created/updated in database for {email}")

                    cursor.execute("SELECT setup_token FROM users WHERE email = ?", (email,))
                    row = cursor.fetchone()
                    if row:
                        token_in_db = row[0]
                        print(f"💡 Setup token in DB for {email}: {token_in_db[:10]}...")
                    else:
                        print(f"⚠️ CRITICAL: No user found in DB after insert for {email}")
                        return '', 500

            except Exception as e:
                print(f"❌ DATABASE ERROR: {e}")
                print(f"❌ ERROR TYPE: {type(e)}")
                print(f"❌ ERROR DETAILS: {str(e)}")
                import traceback
                print("❌ TRACEBACK:")
                traceback.print_exc()
                conn.rollback()
                return str(e), 500

            # Send setup email
            print(f"📧 Attempting to send setup email to {email}")
            print(f"   Email notifier configured: {email_notifier.is_configured()}")

            if email_notifier.is_configured():
                setup_link = f"https://screenshottracker.com/auth/complete-registration?email={email}&token={setup_token}"

                html_content = f"""
                <!DOCTYPE html>
                <html>
                <body>
                    <h2>Welcome to Screenshot Tracker!</h2>
                    <p>Your subscription is active! Please complete your account setup:</p>

                    <p><a href="{setup_link}" style="background: #ff9900; color: white; padding: 12px 30px; 
                          text-decoration: none; border-radius: 5px; display: inline-block;">
                        Set Your Password
                    </a></p>

                    <p>Or copy this link: {setup_link}</p>

                    <p>This link expires in 24 hours.</p>
                </body>
                </html>
                """

                success = email_notifier.send_email(
                    email,
                    "Complete Your Screenshot Tracker Setup",
                    html_content
                )

                if success:
                    print(f"✅ Setup email sent to {email}")
                else:
                    print(f"❌ Failed to send setup email to {email}")

            else:
                print("⚠️ Email notifier not configured - skipping email")

        elif event['type'] == 'customer.subscription.deleted':
            # Handle cancellation
            subscription = event['data']['object']

            # Set subscription_status to 'cancelled' and max_products to 0 so the user can't add more
            if get_db_type() == 'postgresql':
                cursor.execute("""
                    UPDATE users 
                    SET subscription_status = 'cancelled',
                        max_products = 0
                    WHERE stripe_subscription_id = %s
                """, (subscription['id'],))
            else:
                cursor.execute("""
                    UPDATE users 
                    SET subscription_status = 'cancelled',
                        max_products = 0
                    WHERE stripe_subscription_id = ?
                """, (subscription['id'],))
            conn.commit()

        elif event['type'] == 'invoice.payment_succeeded':
            invoice = event['data']['object']

            # Safely get subscription id and customer
            subscription_id = invoice.get('subscription')
            customer_id = invoice.get('customer')
            customer_email = invoice.get('customer_email')  # may be None

            print(f"✅ Invoice payment succeeded. Subscription: {subscription_id}, Customer: {customer_id}, Email: {customer_email}")

            # If invoice has no subscription (one-off invoice), skip it
            if not subscription_id:
                print("⚠️ Invoice has no subscription field — skipping renewal handling.")
                return '', 200

            # Retrieve subscription safely (catch Stripe errors)
            try:
                subscription = stripe.Subscription.retrieve(subscription_id)
            except Exception as e:
                print(f"⚠️ Could not retrieve subscription {subscription_id}: {e}")
                return '', 200

            # Try to get price_id from invoice lines; fallback to subscription
            try:
                price_id = invoice['lines']['data'][0]['price']['id']
            except (KeyError, IndexError, TypeError):
                try:
                    price_id = subscription['items']['data'][0]['price']['id']
                except Exception:
                    print(f"⚠️ Could not find a price_id for subscription {subscription_id}; defaulting duration")
                    price_id = None

            # Map to durations (your existing map)
            duration_map = {
                os.environ.get('STRIPE_AUTHOR_WEEKLY_PRICE'): timedelta(weeks=1),
                os.environ.get('STRIPE_AUTHOR_MONTHLY_PRICE'): timedelta(days=30),
                os.environ.get('STRIPE_AUTHOR_YEARLY_PRICE'): timedelta(days=365),
                os.environ.get('STRIPE_PUBLISHER_WEEKLY_PRICE'): timedelta(weeks=1),
                os.environ.get('STRIPE_PUBLISHER_MONTHLY_PRICE'): timedelta(days=30),
                os.environ.get('STRIPE_PUBLISHER_YEARLY_PRICE'): timedelta(days=365),
            }
            expires_at = datetime.now() + duration_map.get(price_id, timedelta(days=30))

            # Update only subscription_expires and subscription_status — do NOT touch setup_token or password_hash
            try:
                if get_db_type() == 'postgresql':
                    cursor.execute("""
                        UPDATE users
                        SET subscription_expires = %s,
                            subscription_status = 'active'
                        WHERE stripe_subscription_id = %s
                    """, (expires_at, subscription_id))
                else:
                    cursor.execute("""
                        UPDATE users
                        SET subscription_expires = ?,
                            subscription_status = 'active'
                        WHERE stripe_subscription_id = ?
                    """, (expires_at, subscription_id))

                conn.commit()
                print(f"✅ Subscription renewed successfully until {expires_at}")
            except Exception as e:
                print(f"❌ Database update failed for subscription {subscription_id}: {e}")
                conn.rollback()

            return '', 200

        elif event['type'] == 'invoice.payment_failed':
            # Handle failed payment
            invoice = event['data']['object']
            subscription_id = invoice['subscription']

            if get_db_type() == 'postgresql':
                cursor.execute("""
                    UPDATE users 
                    SET subscription_status = 'past_due'
                    WHERE stripe_subscription_id = %s
                """, (subscription_id,))
            else:
                cursor.execute("""
                    UPDATE users 
                    SET subscription_status = 'past_due'
                    WHERE stripe_subscription_id = ?
                """, (subscription_id,))
            conn.commit()

            print(f"⚠️ Payment failed for subscription: {subscription_id}")

        return '', 200

    except Exception as e:
        conn.rollback()
        print(f"Stripe webhook error: {e}")
        return str(e), 500
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.route('/admin/fix_paid_user/<email>')
@login_required  
def fix_paid_user(email):
    if current_user.email not in ['josh.matern@gmail.com']:
        return "Unauthorized", 403

    conn = get_db()
    cursor = conn.cursor()

    setup_token = secrets.token_urlsafe(32)

    cursor.execute("""
        INSERT INTO users (
            email, password_hash, subscription_status, subscription_tier,
            max_products, is_verified, verification_token, verification_token_expiry
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (email) DO UPDATE SET
            subscription_status = 'active',
            subscription_tier = 'author',
            max_products = 2,
            verification_token = EXCLUDED.verification_token
    """, (email, 'PENDING_SETUP', 'active', 'author', 2, False,
          setup_token, datetime.now() + timedelta(hours=24)))

    conn.commit()
    conn.close()

    setup_link = f"https://screenshottracker.com/auth/complete-registration?email={email}&token={setup_token}"

    return f"""
    <h2>User created/updated for {email}</h2>
    <p>Send them this link to set their password:</p>
    <p><a href="{setup_link}">{setup_link}</a></p>
    """

@app.route('/admin/create_paid_user/<email>')
@login_required
def create_paid_user(email):
    if current_user.email not in ['josh.matern@gmail.com']:
        return "Unauthorized", 403

    conn = get_db()
    cursor = conn.cursor()

    setup_token = secrets.token_urlsafe(32)

    if get_db_type() == 'postgresql':
        cursor.execute("""
            INSERT INTO users (
                email, password_hash, subscription_status, subscription_tier,
                max_products, is_verified, verification_token, verification_token_expiry
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (email) DO UPDATE SET
                subscription_status = 'active',
                subscription_tier = 'author',
                max_products = 2
        """, (email, 'PENDING_SETUP', 'active', 'author', 2, False, 
              setup_token, datetime.now() + timedelta(hours=24)))

    conn.commit()
    conn.close()

    # Send setup email
    setup_link = f"https://screenshottracker.com/auth/complete-registration?email={email}&token={setup_token}"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <body>
        <h2>Welcome to Screenshot Tracker!</h2>
        <p>Your subscription is active! Please complete your account setup:</p>

        <p><a href="{setup_link}" style="background: #ff9900; color: white; padding: 12px 30px; 
              text-decoration: none; border-radius: 5px; display: inline-block;">
            Set Your Password
        </a></p>

        <p>Or copy this link: {setup_link}</p>

        <p>This link expires in 24 hours.</p>
    </body>
    </html>
    """

    success = email_notifier.send_email(
        email,
        "Complete Your Screenshot Tracker Setup",
        html_content
    )

    if success:
        print(f"✅ Setup email sent to {email}")
    else:
        print(f"❌ Failed to send setup email to {email}")

    return f"User created for {email}. Setup link: {setup_link}"

@app.route('/admin/fix_stripe_columns')
@login_required
def fix_stripe_columns():
    if current_user.email not in ['josh.matern@gmail.com']:
        return "Unauthorized", 403

    conn = get_db()
    cursor = conn.cursor()

    try:
        if get_db_type() == 'postgresql':
            cursor.execute("""
                ALTER TABLE users 
                ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(100),
                ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(100)
            """)
            conn.commit()
            return "✅ Stripe columns added successfully"
        else:
            return "This is for PostgreSQL only", 400
    except Exception as e:
        conn.rollback()
        return f"Error: {str(e)}", 500
    finally:
        conn.close()

@app.route('/success')
def subscription_success():
    """Page after successful payment"""
    return render_template('success.html', 
        message="Payment successful! Check your email to complete setup.")

@app.route('/cancel')
def subscription_cancel():
    """Page if user cancels payment"""
    return redirect(url_for('pricing'))

@app.route('/change_subscription', methods=['GET', 'POST'])
@login_required
def change_subscription():
    """Change subscription tier"""
    conn = get_db()
    cursor = conn.cursor()

    # Get current subscription
    if get_db_type() == 'postgresql':
        cursor.execute("""
            SELECT stripe_subscription_id, subscription_tier 
            FROM users WHERE id = %s
        """, (current_user.id,))
    else:
        cursor.execute("""
            SELECT stripe_subscription_id, subscription_tier 
            FROM users WHERE id = ?
        """, (current_user.id,))

    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        flash('No active subscription found', 'error')
        return redirect(url_for('pricing'))

    current_subscription_id = user_data[0] if isinstance(user_data, tuple) else user_data['stripe_subscription_id']
    current_tier = user_data[1] if isinstance(user_data, tuple) else user_data['subscription_tier']

    if request.method == 'POST':
        new_price_id = request.form.get('price_id')

        try:
            # Get the subscription from Stripe
            subscription = stripe.Subscription.retrieve(current_subscription_id)

            # Update the subscription with the new price
            stripe.Subscription.modify(
                current_subscription_id,
                items=[{
                    'id': subscription['items']['data'][0]['id'],
                    'price': new_price_id,
                }],
                proration_behavior='always_invoice',  # Charge/credit immediately
            )

            # Update database
            tier_map = {
                os.environ.get('STRIPE_AUTHOR_WEEKLY_PRICE'): ('author', 2),
                os.environ.get('STRIPE_AUTHOR_MONTHLY_PRICE'): ('author', 2),
                os.environ.get('STRIPE_AUTHOR_YEARLY_PRICE'): ('author', 2),
                os.environ.get('STRIPE_PUBLISHER_WEEKLY_PRICE'): ('publisher', 5),
                os.environ.get('STRIPE_PUBLISHER_MONTHLY_PRICE'): ('publisher', 5),
                os.environ.get('STRIPE_PUBLISHER_YEARLY_PRICE'): ('publisher', 5),
            }

            new_tier, new_max_products = tier_map.get(new_price_id, ('author', 2))

            conn = get_db()
            cursor = conn.cursor()

            if get_db_type() == 'postgresql':
                cursor.execute("""
                    UPDATE users 
                    SET subscription_tier = %s, max_products = %s
                    WHERE id = %s
                """, (new_tier, new_max_products, current_user.id))
            else:
                cursor.execute("""
                    UPDATE users 
                    SET subscription_tier = ?, max_products = ?
                    WHERE id = ?
                """, (new_tier, new_max_products, current_user.id))

            conn.commit()
            conn.close()

            flash('Subscription updated successfully!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            flash(f'Error updating subscription: {str(e)}', 'error')
            return redirect(url_for('dashboard'))

    # GET - show change options
    return render_template('change_subscription.html', current_tier=current_tier)

@app.route('/api/next_check_times')
@login_required
def get_next_check_times():
    """Get when each product will be checked next"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT 
                    id,
                    product_title,
                    last_checked,
                    created_at,
                    active,
                    CASE 
                        WHEN active = false THEN NULL
                        WHEN last_checked IS NULL THEN created_at + INTERVAL '60 minutes'
                        ELSE last_checked + INTERVAL '60 minutes'
                    END as next_check
                FROM products
                WHERE user_id = %s
                ORDER BY next_check ASC
            ''', (current_user.id,))
        else:
            cursor.execute('''
                SELECT 
                    id,
                    product_title,
                    last_checked,
                    created_at,
                    active,
                    CASE 
                        WHEN active = 0 THEN NULL
                        WHEN last_checked IS NULL THEN datetime(created_at, '+60 minutes')
                        ELSE datetime(last_checked, '+60 minutes')
                    END as next_check
                FROM products
                WHERE user_id = ?
                ORDER BY next_check ASC
            ''', (current_user.id,))

        products = cursor.fetchall()
        conn.close()

        result = []
        current_time = datetime.now()

        for product in products:
            if isinstance(product, dict):
                product_data = {
                    'id': product['id'],
                    'title': product['product_title'],
                    'active': product['active'],
                    'last_checked': str(product['last_checked']) if product['last_checked'] else None,
                    'next_check': str(product['next_check']) if product['next_check'] else None,
                }
            else:
                product_data = {
                    'id': product[0],
                    'title': product[1],
                    'active': product[4],
                    'last_checked': str(product[2]) if product[2] else None,
                    'next_check': str(product[5]) if product[5] else None,
                }

            # Calculate minutes until next check
            if product_data['next_check'] and product_data['active']:
                next_check_time = datetime.fromisoformat(product_data['next_check'].replace(' ', 'T'))
                time_until = next_check_time - current_time
                minutes_until = int(time_until.total_seconds() / 60)
                product_data['minutes_until_check'] = max(0, minutes_until)
                product_data['status'] = 'due' if minutes_until <= 0 else 'scheduled'
            else:
                product_data['minutes_until_check'] = None
                product_data['status'] = 'paused' if not product_data['active'] else 'never_checked'

            result.append(product_data)

        return jsonify(result)

    except Exception as e:
        if conn:
            conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/check_product/<int:product_id>')
@login_required
@limiter.limit("20 per hour")
def manual_check_product(product_id):
    """Check a single product manually"""
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Verify ownership
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT user_id FROM products 
                WHERE id = %s
            ''', (product_id,))
        else:
            cursor.execute('''
                SELECT user_id FROM products 
                WHERE id = ?
            ''', (product_id,))

        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'Product not found'}), 404

        owner_id = result['user_id'] if isinstance(result, dict) else result[0]

        if owner_id != current_user.id:
            conn.close()
            return jsonify({'error': 'Unauthorized'}), 403

        success = check_single_product(product_id=product_id)

        if success:
            return jsonify({'status': 'success', 'message': 'Product checked successfully'})
        else:
            return jsonify({'error': 'Failed to check product'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def process_achievement_screenshot(screenshot_data, product_id, user_id, achievement_type):
    """Process full screenshot into badge and rank sections"""
    try:
        # Check if PIL is available
        if not PIL_AVAILABLE or Image is None:
            print("⚠️  PIL not available, skipping screenshot processing")
            return {
                'full': None,
                'badge': None,
                'rank': None
            }
        
        # Load screenshot (Image is guaranteed to be available here)
        img = Image.open(io.BytesIO(screenshot_data))
        width, height = img.size

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save full screenshot first (for reference)
        full_filename = f'screenshot_{product_id}_full_{timestamp}.png'
        full_path = os.path.join(SCREENSHOT_DIR, full_filename)
        img.save(full_path)
        print(f"💾 Saved full screenshot: {full_filename}")

        # Create badge section (top 1200px)
        badge_section = img.crop((0, 0, width, min(1200, height)))
        badge_filename = f'screenshot_{product_id}_badge_{timestamp}.png'
        badge_path = os.path.join(SCREENSHOT_DIR, badge_filename)
        badge_section.save(badge_path)
        print(f"💾 Saved badge section: {badge_filename}")

        # Create rank section (from 1800px to end, max 1500px height)
        if height > 1800:
            rank_start = 1800
            rank_end = min(rank_start + 1500, height)
            rank_section = img.crop((0, rank_start, width, rank_end))
            rank_filename = f'screenshot_{product_id}_rank_{timestamp}.png'
            rank_path = os.path.join(SCREENSHOT_DIR, rank_filename)
            rank_section.save(rank_path)
            print(f"💾 Saved rank section: {rank_filename}")
        else:
            rank_filename = None

        return {
            'full': full_filename,
            'badge': badge_filename,
            'rank': rank_filename
        }

    except Exception as e:
        print(f"Error processing screenshot: {e}")
        return None

def save_screenshot(screenshot_data, product_id, user_id, screenshot_type='badge'):
    """Save screenshot with type identifier"""
    if not screenshot_data:
        return None

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'screenshot_{product_id}_{screenshot_type}_{timestamp}.png'
    filepath = os.path.join(SCREENSHOT_DIR, filename)

    try:
        with open(filepath, 'wb') as f:
            f.write(screenshot_data)
        print(f"💾 Saved {screenshot_type} screenshot: {filename}")
        return filename
    except Exception as e:
        print(f"❌ Failed to save screenshot: {e}")
        return None

def check_specific_product(user_id, product_id):
    """Check a specific product"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get the specific product
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT p.product_url, p.current_rank, p.is_bestseller
                FROM products p
                WHERE p.id = %s AND p.user_id = %s
            ''', (product_id, user_id))
        else:
            cursor.execute('''
                SELECT p.product_url, p.current_rank, p.is_bestseller
                FROM products p
                WHERE p.id = ? AND p.user_id = ?
            ''', (product_id, user_id))

        product = cursor.fetchone()
        if not product:
            conn.close()
            return {'error': 'Product not found'}

        if isinstance(product, dict):
            url = product['product_url']
            previous_rank = int(product['current_rank']) if product['current_rank'] else 999999
            was_bestseller = product['is_bestseller']
        else:
            url = product[0]
            previous_rank = int(product[1]) if product[1] else 999999
            was_bestseller = product[2]

        # Scrape and update
        user_monitor = AmazonMonitor.for_user(user_id)
        result = user_monitor.scrape_amazon_page(url)

        if result.get('success'):
            product_info = user_monitor.extract_product_info(result.get('html', ''))

            # Update database
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    UPDATE products 
                    SET current_rank = %s, current_category = %s, 
                        is_bestseller = %s, last_checked = %s
                    WHERE id = %s
                ''', (
                    product_info.get('rank'),
                    product_info.get('category'),
                    product_info.get('is_bestseller', False),
                    datetime.now(),
                    product_id
                ))
            else:
                cursor.execute('''
                    UPDATE products 
                    SET current_rank = ?, current_category = ?, 
                        is_bestseller = ?, last_checked = ?
                    WHERE id = ?
                ''', (
                    product_info.get('rank'),
                    product_info.get('category'),
                    product_info.get('is_bestseller', False),
                    datetime.now(),
                    product_id
                ))

            conn.commit()
            conn.close()

            # Check for achievement
            achievement = None
            current_rank = int(product_info['rank']) if product_info.get('rank') else None

            if product_info.get('is_bestseller') and not was_bestseller:
                achievement = "New Bestseller!"
            elif current_rank and current_rank <= 10 and previous_rank > 10:
                achievement = f"Entered Top 10! (#{current_rank})"

            return {
                'rank': product_info.get('rank'),
                'category': product_info.get('category'),
                'is_bestseller': product_info.get('is_bestseller', False),
                'achievement': achievement
            }

        conn.close()
        return {'error': 'Failed to scrape product'}

    except Exception as e:
        if conn:
            conn.close()
        raise

def check_single_product(product_id, url=None, user_id=None, product_title=None, category=None, target_rank=None):
    """Check single product with two-call strategy"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # If only product_id provided, fetch the details
        if not url or not user_id:
            if get_db_type() == 'postgresql':
                cursor.execute("""
                    SELECT product_url, user_id, product_title, current_category, 
                           current_rank, is_bestseller
                    FROM products WHERE id = %s
                """, (product_id,))
            else:
                cursor.execute("""
                    SELECT product_url, user_id, product_title, current_category,
                           current_rank, is_bestseller  
                    FROM products WHERE id = ?
                """, (product_id,))

            product_data = cursor.fetchone()
            if not product_data:
                conn.close()
                return False

            if isinstance(product_data, dict):
                url = url or product_data['product_url']
                user_id = user_id or product_data['user_id']
                product_title = product_title or product_data['product_title']
                category = category or product_data['current_category']
                previous_rank = product_data.get('current_rank')
                was_bestseller = product_data.get('is_bestseller', False)
            else:
                url = url or product_data[0]
                user_id = user_id or product_data[1]
                product_title = product_title or product_data[2]
                category = category or product_data[3]
                previous_rank = product_data[4] if len(product_data) > 4 else None
                was_bestseller = product_data[5] if len(product_data) > 5 else False

        monitor = AmazonMonitor.for_user(user_id)

        # Get previous state (with safe defaults for missing columns)
        if get_db_type() == 'postgresql':
            cursor.execute("""
                SELECT 
                    COALESCE(last_rank, current_rank) as last_rank,
                    COALESCE(has_bestseller_badge, is_bestseller, FALSE) as has_bestseller_badge,
                    baseline_rank,
                    last_achievement_date
                FROM products WHERE id = %s
            """, (product_id,))
        else:
            cursor.execute("""
                SELECT 
                    COALESCE(last_rank, current_rank) as last_rank,
                    COALESCE(has_bestseller_badge, is_bestseller, 0) as has_bestseller_badge,
                    baseline_rank,
                    last_achievement_date
                FROM products WHERE id = ?
            """, (product_id,))

        prev_data = cursor.fetchone()
        if not prev_data:
            print(f"Product {product_id} not found")
            conn.close()
            return False

        # Handle both dict and tuple with safe defaults
        if isinstance(prev_data, dict):
            prev_rank = prev_data.get('last_rank')
            had_badge = bool(prev_data.get('has_bestseller_badge', False))
            baseline_rank = prev_data.get('baseline_rank')
            last_achievement = prev_data.get('last_achievement_date')
        else:
            prev_rank = prev_data[0] if prev_data[0] is not None else None
            had_badge = bool(prev_data[1]) if prev_data[1] is not None else False
            baseline_rank = prev_data[2] if len(prev_data) > 2 else None
            last_achievement = prev_data[3] if len(prev_data) > 3 else None

        # Convert rank strings to integers safely
        if prev_rank and isinstance(prev_rank, str):
            try:
                prev_rank = int(prev_rank)
            except ValueError:
                prev_rank = None

        if baseline_rank and isinstance(baseline_rank, str):
            try:
                baseline_rank = int(baseline_rank)
            except ValueError:
                baseline_rank = None

        # Set baseline if this is the first check
        if baseline_rank is None and prev_rank:
            baseline_rank = prev_rank
            if get_db_type() == 'postgresql':
                cursor.execute("UPDATE products SET baseline_rank = %s WHERE id = %s", 
                             (baseline_rank, product_id))
            else:
                cursor.execute("UPDATE products SET baseline_rank = ? WHERE id = ?", 
                             (baseline_rank, product_id))
            conn.commit()

        # FIRST CALL - HTML only (10 credits)
        print(f"📊 Checking product: {product_title}")
        result = monitor.scrape_amazon_page(url, need_screenshot=False)

        if not result['success']:
            print(f"❌ Failed to scrape: {result['error']}")
            conn.close()
            return False

        product_info = monitor.extract_product_info(result['html'])
        current_rank = int(product_info['rank']) if product_info['rank'] else None

        # Determine if achievement occurred
        achievements = []

        # Check for new bestseller badge
        if product_info['is_bestseller'] and not had_badge:
            achievements.append('bestseller_badge')
            print("🏆 New bestseller badge detected!")

        # Check for rank improvement from baseline
        if current_rank and baseline_rank:
            if current_rank < baseline_rank * 0.8:  # 20% improvement
                achievements.append('rank_improved')
                print(f"📈 Significant rank improvement: #{baseline_rank} → #{current_rank}")

        # Check if hit target rank
        if current_rank and target_rank and current_rank <= target_rank:
            # Don't trigger if we already captured this recently
            if not last_achievement or (datetime.now() - last_achievement).days > 1:
                achievements.append('target_reached')
                print(f"🎯 Target rank reached: #{current_rank}")

        # SECOND CALL - With screenshot if achievement detected (25 credits)
        screenshot_files = None
        if achievements:
            print(f"🎯 Achievements detected! Capturing screenshot...")
            screenshot_result = monitor.scrape_amazon_page(url, need_screenshot=True)

            if screenshot_result['success'] and screenshot_result['screenshot']:
                # Process the screenshot into sections
                screenshot_files = process_achievement_screenshot(
                    screenshot_result['screenshot'],
                    product_id,
                    user_id,
                    achievements[0]
                )

                if screenshot_files:
                    # Save achievement records
                    for achievement_type in achievements:
                        description = {
                            'bestseller_badge': f"Achieved Bestseller Badge in {category or 'Books'}",
                            'rank_improved': f"Rank improved to #{current_rank} from #{baseline_rank}",
                            'target_reached': f"Reached target rank #{current_rank}"
                        }.get(achievement_type, "Achievement unlocked")

                        # Save with appropriate screenshot
                        screenshot_to_use = screenshot_files['badge'] if 'badge' in achievement_type else screenshot_files['rank']

                        save_achievement(
                            product_id,
                            user_id,
                            achievement_type,
                            screenshot_to_use or screenshot_files['full'],
                            description
                        )

                    # Send email with both screenshots
                    send_achievement_email_with_sections(
                        user_id, 
                        product_title, 
                        achievements,
                        screenshot_files
                    )

        # Update product status
        if get_db_type() == 'postgresql':
            cursor.execute("""
                UPDATE products 
                SET last_rank = %s,
                    has_bestseller_badge = %s,
                    last_checked = %s,
                    last_achievement_date = %s
                WHERE id = %s
            """, (
                current_rank, 
                product_info['is_bestseller'], 
                datetime.now(),
                datetime.now() if achievements else last_achievement,
                product_id
            ))

        conn.commit()
        print(f"✅ Product check complete. Credits used: {10 if not achievements else 35}")
        return True

    except Exception as e:
        conn.rollback()
        print(f"❌ Error checking product: {e}")
        return False
    finally:
        conn.close()

def save_achievement(product_id, user_id, achievement_type, screenshot_filename, description):
    """Save achievement record to database"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        if get_db_type() == 'postgresql':
            cursor.execute("""
                INSERT INTO bestseller_screenshots 
                (product_id, screenshot_data, rank_achieved, category, achieved_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (product_id, screenshot_filename, None, description, datetime.now()))
        else:
            cursor.execute("""
                INSERT INTO bestseller_screenshots 
                (product_id, screenshot_data, rank_achieved, category, achieved_at)
                VALUES (?, ?, ?, ?, ?)
            """, (product_id, screenshot_filename, None, description, datetime.now()))

        conn.commit()
        print(f"✅ Achievement saved: {achievement_type}")
    except Exception as e:
        print(f"❌ Error saving achievement: {e}")
        conn.rollback()
    finally:
        conn.close()

def send_achievement_email_with_sections(user_id, product_title, achievements, screenshot_files):
    """Send email with both screenshot sections"""
    # Get user email
    conn = get_db()
    cursor = conn.cursor()

    if get_db_type() == 'postgresql':
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    else:
        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))

    user = cursor.fetchone()
    conn.close()

    if not user:
        return

    email = user[0] if isinstance(user, tuple) else user['email']

    # Build email content
    achievement_text = ", ".join([
        {
            'bestseller_badge': 'Bestseller Badge',
            'rank_improved': 'Rank Improvement',
            'target_reached': 'Target Rank Reached'
        }.get(a, a) for a in achievements
    ])

    html_content = f"""
    <h2>🎉 Achievement Unlocked!</h2>
    <p>Your product <strong>{product_title}</strong> has achieved: {achievement_text}</p>

    <h3>Product Badge Area:</h3>
    <p>Screenshot showing the product image and any bestseller badges</p>

    <h3>Ranking Details:</h3>
    <p>Screenshot showing the Best Sellers Rank in product details</p>

    <p>View your dashboard for more details!</p>
    """

    # Attach both screenshots if available
    attachments = []
    if screenshot_files:
        for key in ['badge', 'rank']:
            if screenshot_files.get(key):
                filepath = os.path.join(SCREENSHOT_DIR, screenshot_files[key])
                if os.path.exists(filepath):
                    with open(filepath, 'rb') as f:
                        img_data = f.read()
                        img = MIMEImage(img_data)
                        img.add_header('Content-Disposition', 'attachment', 
                                     filename=screenshot_files[key])
                        attachments.append(img)

    email_notifier.send_email(email, f"Achievement: {product_title}", html_content, attachments)

def init_scheduler_if_needed():
    """Initialize scheduler only if enabled and not already running"""
    global scheduler_initialized, scheduler_thread, scheduler_running

    if scheduler_initialized:
        return

    if os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true':
        try:
            print("📅 Starting scheduler in background...")
            scheduler_thread = threading.Thread(
                target=run_scheduler,
                daemon=True,
                name="PerProductScheduler"
            )
            scheduler_thread.start()
            scheduler_initialized = True
            scheduler_running = True
            print("✅ Scheduler started")
        except Exception as e:
            print(f"⚠️ Scheduler failed to start: {e}")
    else:
        print("⚠️ Scheduler disabled via ENABLE_SCHEDULER")

# ============= ENSURE GLOBALS EXIST =============
# Initialize scheduler globals if they don't exist
if 'scheduler_initialized' not in globals():
    scheduler_initialized = False
if 'scheduler_thread' not in globals():
    scheduler_thread = None
if 'scheduler_running' not in globals():
    scheduler_running = False
if 'scheduler_lock' not in globals():
    scheduler_lock = threading.Lock()


# ============= APPLICATION FACTORY =============
def create_app():
    """Application factory pattern for better WSGI compatibility"""
    return app

# ============= AUTOMATIC SCHEDULER START =============
def start_scheduler_with_delay():
    """Start scheduler after a delay to ensure app is ready"""
    global scheduler_initialized, scheduler_thread, scheduler_running, scheduler_lock

    time.sleep(5)  # Wait for app to fully initialize

    if os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true':
        print("📅 Auto-starting scheduler after delay...")
        try:
            ensure_scheduler_running()
        except Exception as e:
            print(f"❌ Failed to start scheduler: {e}")
            import traceback
            traceback.print_exc()

# ============= MAIN EXECUTION =============
print("🚀 Starting Amazon Bestseller Monitor...")

# Start scheduler in background thread after delay
if os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true':
    print("📅 Scheduler will start in 5 seconds...")
    threading.Thread(target=start_scheduler_with_delay, daemon=True).start()

# For development
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)