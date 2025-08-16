# Amazon Bestseller Screenshot Monitor
# A web app to monitor Amazon products and capture bestseller screenshots

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, Blueprint, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import secrets
import string
import sqlite3
import requests
from bs4 import BeautifulSoup, Tag
from bs4.element import NavigableString
import base64
import io
from datetime import datetime, timedelta
import threading
import time
import schedule
import re
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from urllib.parse import urlparse
import json
import smtplib
from flask_talisman import Talisman
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formataddr
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

load_dotenv()
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

def get_db():
    """Get database connection - PostgreSQL in production, SQLite in development"""
    database_url = os.environ.get('DATABASE_URL')

    if database_url:
        # Production: PostgreSQL
        try:
            conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
            return conn
        except Exception as e:
            print(f"❌ PostgreSQL connection failed: {e}")
            raise
    else:
        # Development: SQLite
        conn = sqlite3.connect('amazon_monitor.db')
        conn.row_factory = sqlite3.Row
        return conn

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

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY must be set in environment variables!")

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50 per day", "10 per hour"]
)

app.config['WTF_CSRF_ENABLED'] = True
@app.before_request
def log_request():
    print(f"📍 Request: {request.method} {request.path}")
    if current_user.is_authenticated:
        print(f"   User: {current_user.email}")
    else:
        print("   User: Anonymous")

# Create authentication blueprint for better organization
auth = Blueprint('auth', __name__)

# Initialize Flask-Login with security settings
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'  # type: ignore
login_manager.login_message = 'Please log in to access this page.'
login_manager.session_protection = 'strong'  # Protect against session hijacking

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

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

# ScrapingBee configuration - using environment variables for security
SCRAPINGBEE_API_KEY = os.environ.get('SCRAPINGBEE_SECRET_KEY')
SCRAPINGBEE_URL = 'https://app.scrapingbee.com/api/v1/'

# Validate that the API key is available
if not SCRAPINGBEE_API_KEY:
    print("⚠️  WARNING: SCRAPINGBEE_API_KEY environment variable not set!")
    print("Please add your ScrapingBee API key as a secret in Replit")
    print("Go to: Secrets tab → Add secret → Key: SCRAPINGBEE_API_KEY → Value: your_api_key")

# CSRF Protection
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
print(f"CSRF Enabled: {app.config.get('WTF_CSRF_ENABLED', 'Not Set')}")
print(f"Secret Key Length: {len(app.config['SECRET_KEY'])}")
csrf = CSRFProtect(app)

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

# Initialize Talisman for security headers (disable in development)
if os.environ.get('FLASK_ENV') != 'development':
    Talisman(app, 
             force_https=True,
             strict_transport_security=True,
             content_security_policy=csp,
             session_cookie_secure=True,
             session_cookie_http_only=True)

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

@app.errorhandler(404)
def bad_request(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('The form submission has expired. Please try again.', 'error')
    return redirect(request.referrer or url_for('index'))

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

class EmailNotifier:
    """Handle all email notifications for the application"""
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.username = SMTP_USERNAME
        self.password = SMTP_PASSWORD
        self.sender_email = SENDER_EMAIL
        self.sender_name = SENDER_NAME

    def is_configured(self):
        """Check if email settings are configured"""
        return all([self.smtp_server, self.username, self.password])

    def send_email(self, recipient, subject, html_content, attachments=None):
        """Generic email sending method"""
        if not self.is_configured():
            print("❌ Email settings not configured")
            return False

        try:
            msg = MIMEMultipart('related')
            msg['Subject'] = subject
            msg['From'] = formataddr((self.sender_name, self.sender_email or 'default@example.com'))
            msg['To'] = recipient

            # Attach HTML content
            msg.attach(MIMEText(html_content, 'html'))

            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    msg.attach(attachment)

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                try:
                    if not self.username or not self.password:
                        raise ValueError("SMTP username or password is not configured")
                    server.login(self.username, self.password)
                except Exception as e:
                    print("❌ Could not login to email server:", str(e))
                    return False
                server.send_message(msg)

            print(f"✅ Email sent successfully to {recipient}")
            return True

        except Exception as e:
            print(f"❌ Failed to send email: {e}")
            return False

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

                <p>Thanks for joining our beta! Please verify your email address to start monitoring your Amazon products and capturing those valuable ranking screenshots.</p>

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
            "[Beta] Verify Your Email - Amazon Screenshot Tracker",
            html_content
        )

    def get_email_footer(self):
        """Reusable professional email footer for all emails"""
        return """
        <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #eee;">
            <div style="text-align: center; color: #666; font-size: 14px;">
                <p><strong>Amazon Screenshot Tracker</strong> - Currently in Beta 🚀</p>
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
            "[Beta] Password Reset - Amazon Screenshot Tracker",
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
                <h1>🏆 [Beta] Achievement Unlocked!</h1>
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
            f"[Beta] 🏆 Achievement: {product_info['title'][:50]}...",
            html_content,
            attachments
        )

# Initialize email notifier AFTER the class definition
email_notifier = EmailNotifier()

# Print email configuration status
if email_notifier.is_configured():
    print("✅ Email notifications configured")
else:
    print("⚠️ Email notifications not configured - emails will not be sent")
    print("To enable emails, set these environment variables:")
    print("  - SMTP_SERVER")
    print("  - SMTP_USERNAME") 
    print("  - SMTP_PASSWORD")

class APIKeyEncryption:
    def __init__(self):
        # Generate a key from your secret
        secret = app.config['SECRET_KEY'].encode()
        self.cipher = Fernet(base64.urlsafe_b64encode(secret[:32].ljust(32, b'0')))

    def encrypt(self, api_key):
        """Encrypt API key before storing"""
        if not api_key:
            return None
        return self.cipher.encrypt(api_key.encode()).decode()

    def decrypt(self, encrypted_key):
        """Decrypt API key for use"""
        if not encrypted_key:
            return None
        return self.cipher.decrypt(encrypted_key.encode()).decode()

# Initialize encryption
api_encryption = APIKeyEncryption()

class DatabaseManager:
    def __init__(self):
        self.init_db()

    def get_db_type(self):
        """Determine if we're using PostgreSQL or SQLite"""
        return 'postgresql' if os.environ.get('DATABASE_URL') else 'sqlite'

    def init_db(self):
        conn = get_db()
        cursor = conn.cursor()
        db_type = self.get_db_type()

        try:
            if db_type == 'postgresql':
                print("🐘 Initializing PostgreSQL tables...")
                self.create_postgresql_tables(cursor)
            else:
                print("🗃️ Initializing SQLite tables...")
                self.create_sqlite_tables(cursor)

            conn.commit()
            print(f"✅ {db_type.title()} database initialized successfully")
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()

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

class User(UserMixin):
    """Enhanced User model with additional security features"""
    def __init__(self, id, email, full_name=None, is_verified=False, is_active=True):
        self.id = id
        self.email = email
        self.full_name = full_name
        self.is_verified = is_verified
        self.is_active = is_active

    @property
    def is_active(self):
        """Override is_active property/method to provide active state"""
        return self._is_active
    @is_active.setter
    def is_active(self, value):
        self._is_active = value

    @staticmethod
    def get(user_id):
        """Get user by ID with error handling"""
        try:
            conn = sqlite3.connect('amazon_monitor.db')
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, email, full_name, is_verified, is_active 
                FROM users WHERE id = ?
            ''', (user_id,))
            user_data = cursor.fetchone()
            conn.close()

            if user_data and user_data[4]:  # Check if active
                return User(user_data[0], user_data[1], user_data[2], 
                          bool(user_data[3]), bool(user_data[4]))
        except Exception as e:
            print(f"Error loading user: {e}")
        return None

    @staticmethod
    def get_by_email(email):
        """Get user by email with case-insensitive search"""
        try:
            conn = sqlite3.connect('amazon_monitor.db')
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, email, full_name, is_verified, is_active 
                FROM users WHERE LOWER(email) = LOWER(?)
            ''', (email,))
            user_data = cursor.fetchone()
            conn.close()

            if user_data:
                return User(user_data[0], user_data[1], user_data[2], 
                          bool(user_data[3]), bool(user_data[4]))
        except Exception as e:
            print(f"Error finding user by email: {e}")
        return None

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    return User.get(user_id)

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

# Authentication routes with best practices
@auth.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with validation"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()

        # Validate inputs
        errors = []

        if not email or not validate_email(email):
            errors.append('Please enter a valid email address')

        if password != confirm_password:
            errors.append('Passwords do not match')

        password_errors = validate_password(password)
        errors.extend(password_errors)

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html', email=email, full_name=full_name)

        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        try:
            # Check if user exists
            cursor.execute('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', (email,))
            if cursor.fetchone():
                flash('An account with this email already exists', 'error')
                return render_template('auth/register.html')

            # Create user with secure password hash
            password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            verification_token = secrets.token_urlsafe(32)
            token_expiry = datetime.now() + timedelta(hours=24)

            cursor.execute('''
                INSERT INTO users (email, password_hash, full_name, verification_token, verification_token_expiry)
                VALUES (?, ?, ?, ?, ?)
            ''', (email, password_hash, full_name, verification_token, token_expiry))

            user_id = cursor.lastrowid

            # Store verification token
            cursor.execute('''
                INSERT INTO email_verifications (user_id, token)
                VALUES (?, ?)
            ''', (user_id, verification_token))

            conn.commit()

            # Send verification email
            if email_notifier.is_configured():
                email_notifier.send_verification_email(email, verification_token)
                flash('Registration successful! Please check your email to verify your account.', 'success')
            else:
                # For development without email
                cursor.execute('UPDATE users SET is_verified = 1 WHERE id = ?', (user_id,))
                conn.commit()
                flash('Registration successful! You can now log in.', 'success')

            return redirect(url_for('auth.login'))

        except Exception as e:
            conn.rollback()
            print(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'error')
        finally:
            conn.close()

    return render_template('auth/register.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """User login with security measures - FIXED to prevent redirect loops"""
    # If already authenticated, go to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # For GET requests, just show the login form
    if request.method == 'GET':
        return render_template('auth/login.html')

    # Handle POST (login attempt)
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        if not email or not password:
            flash('Please enter both email and password', 'error')
            return render_template('auth/login.html')

        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        try:
            # Get user with security checks
            cursor.execute('''
                SELECT id, password_hash, is_verified, is_active, full_name,
                       failed_login_attempts, account_locked_until
                FROM users WHERE LOWER(email) = LOWER(?)
            ''', (email,))

            user_data = cursor.fetchone()

            # Log login attempt
            cursor.execute('''
                INSERT INTO login_history (user_id, ip_address, user_agent, success)
                VALUES (?, ?, ?, ?)
            ''', (
                user_data[0] if user_data else None,
                request.remote_addr,
                request.headers.get('User-Agent', '')[:200],
                False  # Will update if successful
            ))

            login_history_id = cursor.lastrowid

            if not user_data:
                flash('Invalid email or password', 'error')
                conn.commit()
                conn.close()
                return render_template('auth/login.html')

            user_id, password_hash, is_verified, is_active, full_name, failed_attempts, locked_until = user_data

            # Check if account is locked
            if locked_until and datetime.now() < datetime.fromisoformat(locked_until):
                flash('Account is temporarily locked due to too many failed attempts', 'error')
                conn.commit()
                conn.close()
                return render_template('auth/login.html')

            # Check if account is active
            if not is_active:
                flash('This account has been deactivated. Please contact support.', 'error')
                conn.commit()
                conn.close()
                return render_template('auth/login.html')

            # Verify password
            if not check_password_hash(password_hash, password):
                # Increment failed attempts
                failed_attempts = (failed_attempts or 0) + 1
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = ?, last_failed_login = ?
                    WHERE id = ?
                ''', (failed_attempts, datetime.now(), user_id))

                # Lock account after 5 failed attempts
                if failed_attempts >= 5:
                    locked_until = datetime.now() + timedelta(minutes=30)
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

            # Check if email is verified (optional)
            if not is_verified and email_notifier.is_configured():
                flash('Please verify your email before logging in. Check your inbox for the verification link.', 'warning')
                conn.commit()
                conn.close()
                return render_template('auth/login.html')

            # Successful login
            user = User(user_id, email, full_name, is_verified, is_active)
            login_user(user, remember=remember)

            # Update successful login
            cursor.execute('''
                UPDATE users 
                SET last_login = ?, failed_login_attempts = 0, account_locked_until = NULL
                WHERE id = ?
            ''', (datetime.now(), user_id))

            # Update login history
            cursor.execute('''
                UPDATE login_history SET success = 1 WHERE id = ?
            ''', (login_history_id,))

            conn.commit()
            conn.close()

            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):  # Prevent open redirect
                return redirect(next_page)
            return redirect(url_for('dashboard'))

        except Exception as e:
            print(f"Login error: {e}")
            flash('An error occurred during login. Please try again.', 'error')
            conn.close()
            return render_template('auth/login.html')

    # Should never reach here, but just in case
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
    """Verify email with token"""
    token = request.args.get('token')
    if not token:
        flash('Invalid verification link!', 'error')
        return redirect(url_for('auth.login'))

    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    try:
        # Check if token is valid and not expired
        cursor.execute('''
            SELECT id FROM users 
            WHERE verification_token = ? AND 
                  (verification_token_expiry IS NULL OR verification_token_expiry > ?)
        ''', (token, datetime.now()))

        user = cursor.fetchone()

        if user:
            # Mark user as verified
            cursor.execute('''
                UPDATE users 
                SET is_verified = 1, 
                    verification_token = NULL,
                    verification_token_expiry = NULL 
                WHERE verification_token = ?
            ''', (token,))

            conn.commit()
            flash('Email verified successfully! You can now log in.', 'success')
        else:
            flash('Invalid or expired verification link!', 'error')

    except Exception as e:
        print(f"Email verification error: {e}")
        flash('An error occurred during verification.', 'error')
    finally:
        conn.close()

    return redirect(url_for('auth.login'))

@app.route('/test-email')
@login_required
def test_email():
    """Test email configuration"""
    if current_user.email != 'your-admin-email@gmail.com':  # Replace with your email
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

# Register blueprint
app.register_blueprint(auth, url_prefix='/auth')

# Additional security headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

class AmazonMonitor:
    def __init__(self, api_key=None):
        self.api_key = api_key or SCRAPINGBEE_API_KEY  # Fallback to system key

    @classmethod
    def for_user(cls, user_id):
        """Create monitor instance with user's API key"""
        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()

        if result and result[0]:
            try:
                decrypted_key = api_encryption.decrypt(result[0])
            except Exception as e:
                print(f"Error decrypting API key for user {user_id}: {e}")
                decrypted_key = None
            if decrypted_key:
                return cls(decrypted_key)
        print(f"No user-specific API key found for user {user_id}. Using system default.")
        return cls()  # Use system default if no user key
    
    def scrape_amazon_page(self, url):
        """Use ScrapingBee to scrape Amazon page and take screenshot"""
        if not self.api_key:
            print("❌ ScrapingBee API key not configured")
            return {'success': False, 'error': 'ScrapingBee API key not configured'}

        try:
            print(f"🔄 Starting ScrapingBee request for: {url}")

            # CORRECTED parameters with render_js for screenshots
            params = {
                'api_key': self.api_key,
                'url': url,
                'render_js': 'true',  # REQUIRED for screenshots!
                'screenshot': 'true',
                'json_response': 'true',  # To get both HTML and screenshot
                'screenshot_full_page': 'false',  # Just viewport for efficiency
                'wait': '3000',  # Wait 3 seconds for page to fully load
                'premium_proxy': 'true',
                'country_code': 'us',
                # Wait for key elements to ensure page is loaded
                'wait_for': '#productTitle, h1#title, span.a-badge-text',
                # block_resources automatically set to false when screenshot=true
            }

            print("📤 Making request to ScrapingBee API with JavaScript rendering...")
            response = requests.get(SCRAPINGBEE_URL, params=params, timeout=60)

            print(f"📥 ScrapingBee response status: {response.status_code}")

            if response.status_code == 200:
                print("✅ ScrapingBee request successful")

                # With json_response=true, the response is JSON
                try:
                    response_data = response.json()
                    html_content = response_data.get('body', '')
                    screenshot_data = response_data.get('screenshot', '')

                    print(f"📄 HTML content length: {len(html_content)} characters")
                    print(f"📸 Screenshot data present: {'Yes' if screenshot_data else 'No'}")

                    if screenshot_data:
                        print(f"📸 Screenshot size: {len(screenshot_data)} characters")

                    return {
                        'html': html_content,
                        'screenshot': screenshot_data,
                        'success': True
                    }
                except json.JSONDecodeError:
                    # Fallback if JSON parsing fails
                    print("⚠️ JSON response parsing failed, trying legacy method")
                    return {
                        'html': response.text,
                        'screenshot': response.headers.get('Spb-Screenshot'),
                        'success': True
                    }
            else:
                error_msg = f'HTTP {response.status_code}: {response.text[:500]}'
                print(f"❌ ScrapingBee error: {error_msg}")

                # Check if it's a rate limit error
                if response.status_code == 429:
                    print("⚠️ Rate limit reached - consider adding delay between requests")
                elif response.status_code == 400:
                    print("⚠️ Bad request - check API parameters")

                return {'success': False, 'error': error_msg}

        except requests.exceptions.Timeout:
            error_msg = 'ScrapingBee request timed out (60s)'
            print(f"⏰ {error_msg}")
            return {'success': False, 'error': error_msg}
        except Exception as e:
            error_msg = f'ScrapingBee request failed: {str(e)}'
            print(f"💥 {error_msg}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': error_msg}

    def extract_product_info(self, html):
        """Extract product ranking and bestseller info from Amazon HTML"""
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

            # Method 1: Standard product title
            title_element = soup.find('span', {'id': 'productTitle'})
            if not title_element:
                # Method 2: Try alternative title locations for Kindle books
                title_element = soup.find('h1', {'id': 'title'})
                if not title_element:
                    # Method 3: Look for any h1 with product title
                    title_element = soup.find('h1', class_=re.compile(r'title', re.I))

            if title_element:
                # Extract text from all child elements
                product_info['title'] = ' '.join(title_element.stripped_strings)
                print(f"📋 Found title: {product_info['title'][:100]}...")
            else:
                print("❌ No product title found - trying meta tags")
                # Fallback: Try meta tags for title
                meta_title = soup.find('meta', {'property': 'og:title'})
                if meta_title and isinstance(meta_title, Tag):
                    title_content = meta_title.attrs.get('content')
                    if title_content:
                        product_info['title'] = title_content
                        print(f"📋 Found title in meta: {product_info['title'][:100]}...")

            # Look for bestseller badges - Multiple methods
            print("🔍 Searching for bestseller indicators...")

            # Method 1: Look for bestseller badge images
            badge_imgs = soup.find_all('img', alt=lambda x: bool(x) and 'best seller' in x.lower())
            if badge_imgs:
                product_info['is_bestseller'] = True
                print("🏆 Found bestseller badge image!")

            # Method 2: Look for bestseller text in spans/divs with specific classes
            bestseller_selectors = [
                ('span', {'class': 'a-badge-text'}),
                ('span', {'class': 'ac-badge-text'}),
                ('div', {'class': 'badge-wrapper'}),
                ('span', {'class': 'best-seller-badge'}),
                ('a', {'class': 'badge-link'})
            ]

            for tag, attrs in bestseller_selectors:
                elements = soup.find_all(tag, attrs)
                for elem in elements:
                    if elem and isinstance(elem, Tag):
                        text = elem.get_text().strip()
                        if re.search(r'best\s*seller|#1|amazon\'s\s*choice', text, re.I):
                            product_info['is_bestseller'] = True
                            print(f"🏆 Found bestseller indicator in {tag}: {text}")
                            # Try to extract category
                            parent = elem.parent
                            if parent:
                                full_text = parent.get_text()
                                category_match = re.search(r'in\s+([^#\n]+)', full_text)
                                if category_match:
                                    category = category_match.group(1).strip()
                                    product_info['bestseller_categories'].append(category)

            # Method 3: Look for bestseller in page content with context
            all_text_elements = soup.find_all(text=re.compile(r'Best\s*Seller|#1', re.I))
            for text_elem in all_text_elements[:10]:  # Limit to first 10 to avoid false positives
                if text_elem and text_elem.parent:
                    parent_text = text_elem.parent.get_text()
                    if len(parent_text) < 200:  # Avoid huge text blocks
                        if re.search(r'(#1|Best\s*Seller)\s+in', parent_text, re.I):
                            product_info['is_bestseller'] = True
                            print(f"🏆 Found bestseller in text: {parent_text[:100]}...")

            # Extract ranking information
            print("🔍 Searching for ranking information...")

            # Method 1: Look for Best Sellers Rank in detail sections
            rank_patterns = [
                r'Best\s*Sellers\s*Rank[:\s]*#?([\d,]+)\s+in\s+([^(\n]+)',
                r'#([\d,]+)\s+in\s+([^(\n#]+)',
                r'Best\s*Sellers\s*Rank[:\s]*([^#]*?)#([\d,]+)\s+in\s+([^(\n]+)'
            ]

            # Search in common ranking locations
            rank_containers = [
                soup.find('div', {'id': 'detailBulletsWrapper_feature_div'}),
                soup.find('div', {'id': 'productDetails_feature_div'}),
                soup.find('div', {'id': 'detail_bullets_id'}),
                soup.find('table', {'id': 'productDetails_detailBullets_sections1'}),
                soup.find('div', {'class': 'content-grid-block'})
            ]

            # Also search the entire page if needed
            rank_containers.append(soup)

            for container in rank_containers:
                if container and isinstance(container, Tag):
                    container_text = container.get_text()
                    for pattern in rank_patterns:
                        matches = re.findall(pattern, container_text, re.I)
                        if matches:
                            for match in matches:
                                if len(match) >= 2:
                                    if match[0].isdigit():
                                        rank_num = match[0]
                                        category = match[1]
                                    else:
                                        rank_num = match[1] if len(match) > 2 else match[0]
                                        category = match[2] if len(match) > 2 else match[1]

                                    # Clean up the data
                                    rank_num = rank_num.replace(',', '').strip()
                                    category = category.strip().split('(')[0].strip()

                                    if rank_num.isdigit() and len(category) > 2:
                                        product_info['rank'] = rank_num
                                        product_info['category'] = category
                                        print(f"📈 Found rank: #{rank_num} in {category}")

                                        # Check if this is a #1 rank
                                        if rank_num == '1':
                                            product_info['is_bestseller'] = True
                                            print("🏆 Product is #1 - marking as bestseller!")
                                        break
                        if product_info['rank']:
                            break
                    if product_info['rank']:
                        break

            # Debug output
            if not product_info['rank']:
                print("⚠️ Could not find ranking - dumping sample HTML for debugging")
                # Look for any text containing "rank" for debugging
                rank_texts = soup.find_all(text=re.compile(r'rank|#\d+\s+in', re.I))
                for i, text in enumerate(rank_texts[:5]):
                    if text is not None and isinstance(text, str) and len(text.strip()) > 10:
                        print(f"  Sample {i+1}: {text.strip()[:100]}...")

        except Exception as e:
            print(f"❌ Error extracting product info: {e}")
            import traceback
            traceback.print_exc()

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

# Initialize components
db_manager = DatabaseManager()
monitor = AmazonMonitor(SCRAPINGBEE_API_KEY)

@app.route('/')
def index():
    """Landing page - FIXED to prevent loops and handle errors"""
    try:
        if current_user.is_authenticated:
            # Try dashboard first, fallback to landing if it fails
            try:
                return dashboard_view()
            except Exception as e:
                print(f"❌ Dashboard error for authenticated user: {e}")
                # Log them out and show landing instead of crashing
                from flask_login import logout_user
                logout_user()
                return render_template('landing.html')
        else:
            # Show landing page for anonymous users
            return render_template('landing.html')
    except Exception as e:
        print(f"❌ Critical error in index route: {e}")
        import traceback
        traceback.print_exc()
        # Absolute fallback - simple HTML response
        return """
        <h1>🏆 Amazon Screenshot Tracker</h1>
        <p>Service is starting up...</p>
        <a href="/auth/login">Login</a> | <a href="/auth/register">Register</a>
        """, 200

@app.route('/add_product_form')
@login_required
def add_product_form():
    """Show the add product form"""
    return render_template('add_product.html')

@app.route('/add_product', methods=['POST'])
@limiter.limit("2 per minute")
@login_required
def add_product():
    """Add a new product to monitor - ALWAYS captures initial screenshot"""
    print("🚀 Starting add_product route")

    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Check if API key exists and user has one
    try:
        cursor.execute("PRAGMA table_info(users)")
        user_columns = [column[1] for column in cursor.fetchall()]

        if 'scrapingbee_api_key' in user_columns:
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (current_user.id,))
            result = cursor.fetchone()

            if not result or not result[0]:
                print("❌ No API key found for user")
                flash('Please add your ScrapingBee API key in settings before adding products.', 'error')
                conn.close()
                return redirect(url_for('settings'))
            else:
                print(f"✅ Found API key for user {current_user.email}")
        else:
            print("❌ API key column doesn't exist")
            flash('Database migration needed. Please restart the application.', 'error')
            conn.close()
            return redirect(url_for('dashboard'))

    except Exception as e:
        print(f"❌ Error checking API key: {e}")
        flash('Please configure your ScrapingBee API key in settings.', 'error')
        conn.close()
        return redirect(url_for('settings'))

    # Get form data
    url = request.form.get('url', '').strip()
    target_categories = request.form.get('target_categories', '').strip()

    print(f"📦 Product URL: {url}")
    print(f"🎯 Target categories: {target_categories}")

    if not url:
        print("❌ No URL provided")
        flash('URL is required!', 'error')
        conn.close()
        return redirect(url_for('add_product_form'))

    # Validate URL
    if 'amazon.' not in url.lower():
        print("❌ Invalid Amazon URL")
        flash('Please provide a valid Amazon product URL', 'error')
        conn.close()
        return redirect(url_for('add_product_form'))

    # Use user's monitor instance
    try:
        user_monitor = AmazonMonitor.for_user(current_user.id)
        print(f"🔧 Created monitor instance for user {current_user.id}")
    except Exception as e:
        print(f"❌ Error creating monitor: {e}")
        flash('Error initializing product monitor. Please check your API key.', 'error')
        conn.close()
        return redirect(url_for('settings'))

    try:
        # Initial scrape to get product info WITH SCREENSHOT
        print("🔍 Starting initial scrape with screenshot capture...")
        scrape_result = user_monitor.scrape_amazon_page(url)

        if not scrape_result.get('success'):
            error_msg = scrape_result.get('error', 'Unknown error')
            print(f"❌ Scrape failed: {error_msg}")

            # Check for specific error types
            if '401' in str(error_msg) or 'unauthorized' in str(error_msg).lower():
                flash('Invalid API key. Please check your ScrapingBee settings.', 'error')
                conn.close()
                return redirect(url_for('settings'))
            elif '429' in str(error_msg) or 'rate limit' in str(error_msg).lower():
                flash('API rate limit reached. Please try again later.', 'error')
            else:
                flash(f'Error accessing product page: {error_msg}', 'error')

            conn.close()
            return redirect(url_for('add_product_form'))

        print("✅ Scrape successful!")
        print("🔄 Extracting product information...")

        product_info = user_monitor.extract_product_info(scrape_result['html'])
        print(f"📊 Product info extracted: {product_info}")

        # Save to database with user_id
        print("💾 Saving to database...")
        cursor.execute('''
            INSERT INTO products (user_id, user_email, product_url, product_title, current_rank, 
                                current_category, is_bestseller, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            current_user.id, current_user.email, url, 
            product_info.get('title', 'Unknown Product'), 
            product_info.get('rank'),
            product_info.get('category'), 
            product_info.get('is_bestseller', False), 
            datetime.now()
        ))

        product_id = cursor.lastrowid
        print(f"✅ Saved product with ID: {product_id}")

        # Process target categories if provided
        if target_categories:
            categories = [cat.strip() for cat in target_categories.split(',') if cat.strip()]
            for category in categories:
                if ':' in category:
                    cat_name, target_rank_str = category.split(':', 1)
                    try:
                        target_rank = int(target_rank_str.strip())
                    except ValueError:
                        target_rank = 1
                else:
                    cat_name = category
                    target_rank = 1

                cursor.execute('''
                    INSERT INTO target_categories (product_id, category_name, target_rank)
                    VALUES (?, ?, ?)
                ''', (product_id, cat_name.strip(), target_rank))

                print(f"🎯 Added target category: {cat_name} (Rank goal: #{target_rank})")

        # Save initial ranking
        cursor.execute('''
            INSERT INTO rankings (product_id, rank_number, category, is_bestseller, checked_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            product_id, 
            int(product_info['rank']) if product_info.get('rank') else None,
            product_info.get('category'), 
            product_info.get('is_bestseller', False), 
            datetime.now()
        ))

        # ALWAYS SAVE INITIAL SCREENSHOT (not just for bestsellers)
        if scrape_result.get('screenshot'):
            print("📸 Saving initial baseline screenshot...")

            # Create a new table for baseline screenshots if it doesn't exist
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

            # Save baseline screenshot
            cursor.execute('''
                INSERT OR REPLACE INTO baseline_screenshots 
                (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                product_id, 
                scrape_result['screenshot'], 
                product_info.get('rank'),
                product_info.get('category'), 
                datetime.now()
            ))

            print("✅ Baseline screenshot saved!")

            # If it's ALSO a bestseller on first check, save to bestseller screenshots too
            if product_info.get('is_bestseller'):
                print("🏆 Product is already a bestseller! Saving to achievements...")
                cursor.execute('''
                    INSERT INTO bestseller_screenshots 
                    (product_id, screenshot_data, rank_achieved, category, achieved_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    product_id, 
                    scrape_result['screenshot'], 
                    product_info.get('rank'),
                    product_info.get('category'), 
                    datetime.now()
                ))
        else:
            print("⚠️ No screenshot data received from ScrapingBee")

        conn.commit()
        conn.close()

        # Success message with product title
        product_title = product_info.get('title', 'Product')
        if len(product_title) > 50:
            product_title = product_title[:50] + '...'

        success_msg = f'✅ Successfully added "{product_title}" to monitoring with initial screenshot!'
        print(success_msg)
        flash(success_msg, 'success')

        # Redirect to dashboard
        return redirect(url_for('dashboard'))

    except Exception as e:
        conn.close()
        error_msg = f'Error adding product: {str(e)}'
        print(f"💥 {error_msg}")
        import traceback
        traceback.print_exc()
        flash(error_msg, 'error')
        return redirect(url_for('add_product_form'))

# Add a route to view baseline screenshots
@app.route('/baseline_screenshot/<int:product_id>')
@login_required
def view_baseline_screenshot(product_id):
    """View the initial baseline screenshot for a product"""
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Verify the product belongs to the user
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
    cursor.execute('''
        SELECT screenshot_data, initial_rank, initial_category, captured_at
        FROM baseline_screenshots
        WHERE product_id = ?
    ''', (product_id,))

    result = cursor.fetchone()
    conn.close()

    if result and result[0]:
        try:
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
                as_attachment=False,
                download_name=f'baseline_product_{product_id}.png'
            )
        except Exception as e:
            print(f"❌ Error decoding baseline screenshot: {e}")
            return f"Error loading screenshot: {str(e)}", 500

    # Return a placeholder image if no baseline exists
    return """
    <div style="padding: 50px; text-align: center; background: #f5f5f5;">
        <h2>📷 No baseline screenshot available</h2>
        <p>This product may have been added before baseline screenshots were implemented.</p>
    </div>
    """, 404

@app.route('/get_achievement_count/<int:product_id>')
@login_required
def get_achievement_count(product_id):
    """Get count of achievement screenshots for a product"""
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Verify product belongs to user and get achievement count
    cursor.execute('''
        SELECT COUNT(bs.id)
        FROM bestseller_screenshots bs
        JOIN products p ON bs.product_id = p.id
        WHERE bs.product_id = ? AND p.user_id = ?
    ''', (product_id, current_user.id))

    count = cursor.fetchone()[0]
    if count >= 5:  # Beta limit
        flash('Beta limit: Maximum 5 products per user', 'warning')
        return redirect(url_for('dashboard'))
    conn.close()

    return jsonify({'count': count})

@app.route('/latest_achievement/<int:product_id>')
@login_required
def get_latest_achievement(product_id):
    """Get the latest achievement screenshot ID for a product"""
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Get the most recent achievement screenshot
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
        return jsonify({
            'screenshot_id': result[0],
            'rank': result[1],
            'category': result[2],
            'achieved_at': result[3]
        })

    return jsonify({'screenshot_id': None})

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
    """Dashboard that uses current_user instead of email parameter"""
    return dashboard_view()

def dashboard_view():
    """Dashboard view with API key check"""
    try:
        print(f"🔍 Dashboard called for user: {current_user.is_authenticated}")

        if not current_user.is_authenticated:
            print("❌ User not authenticated in dashboard_view")
            return redirect(url_for('auth.login'))

        user_email = current_user.email
        user_id = current_user.id
        print(f"✅ Processing dashboard for user: {user_email}")

        # Use context manager for database connection
        conn = get_db()
        try:
            cursor = conn.cursor()

            # Check if user has API key
            has_api_key = False
            try:
                cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (user_id,))
                result = cursor.fetchone()
                has_api_key = bool(result and result[0])
            except Exception as api_check_error:
                print(f"⚠️ API key check failed: {api_check_error}")
                has_api_key = False

            # Get user's products
            if hasattr(current_user, 'id'):
                cursor.execute('''
                    SELECT id, product_title, current_rank, current_category, is_bestseller, 
                           last_checked, created_at, active
                    FROM products 
                    WHERE user_id = %s OR user_email = %s
                    ORDER BY created_at DESC
                ''', (user_id, user_email))
            else:
                cursor.execute('''
                    SELECT id, product_title, current_rank, current_category, is_bestseller, 
                           last_checked, created_at, active
                    FROM products 
                    WHERE user_email = %s
                    ORDER BY created_at DESC
                ''', (user_email,))

            products = cursor.fetchall()

            # Get bestseller screenshots for user
            if hasattr(current_user, 'id'):
                cursor.execute('''
                    SELECT bs.id, p.product_title, bs.rank_achieved, bs.category, bs.achieved_at
                    FROM bestseller_screenshots bs
                    JOIN products p ON bs.product_id = p.id
                    WHERE p.user_id = %s OR p.user_email = %s
                    ORDER BY bs.achieved_at DESC
                ''', (user_id, user_email))
            else:
                cursor.execute('''
                    SELECT bs.id, p.product_title, bs.rank_achieved, bs.category, bs.achieved_at
                    FROM bestseller_screenshots bs
                    JOIN products p ON bs.product_id = p.id
                    WHERE p.user_email = %s
                    ORDER BY bs.achieved_at DESC
                ''', (user_email,))

            screenshots = cursor.fetchall()

            return render_template('dashboard.html', 
                 email=user_email,
                 products=products, 
                 screenshots=screenshots,
                 has_api_key=has_api_key)

        finally:
            # Always close database connection
            conn.close()

    except Exception as e:
        print(f"❌ Dashboard error: {e}")
        import traceback
        traceback.print_exc()

        # Return a simple error page instead of crashing
        flash('Dashboard temporarily unavailable. Please try again.', 'error')
        return render_template('landing.html')

# Settings page route
@app.route('/settings')
@login_required
def settings():
    """User settings page"""
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (current_user.id,))
    result = cursor.fetchone()
    conn.close()

    # Don't show the actual key, just indicate if it's set
    has_api_key = bool(result and result[0])

    return render_template('settings.html', user=current_user, has_api_key=has_api_key)

@app.route('/update_api_key', methods=['POST'])
@login_required
def update_api_key():
    """Update user's ScrapingBee API key"""
    api_key = request.form.get('api_key', '').strip()

    if not api_key:
        flash('API key cannot be empty', 'error')
        return redirect(url_for('settings'))

    # Basic check of API key if it's too short
    if len(api_key) < 20:
        flash('API key seems too short. Please check your ScrapingBee dashboard.', 'error')
        return redirect(url_for('settings'))

    # Optional: Test the API key with a simple request
    test_monitor = AmazonMonitor(api_key)
    print(f"🔑 Testing API key: {api_key[:10]}...")  # Only log first 10 chars for security
    
    # Try a simple test request to validate the key
    try:
        test_result = test_monitor.scrape_amazon_page('https://www.amazon.com')

        if test_result.get('error'):
            # Check if it's an API key error
            error_msg = str(test_result.get('error', ''))
            if 'unauthorized' in error_msg.lower() or '401' in error_msg:
                flash('Invalid API key. Please check your ScrapingBee dashboard for the correct key.', 'error')
                return redirect(url_for('settings'))
            elif 'rate limit' in error_msg.lower() or '429' in error_msg:
                # Rate limit means the key is valid but over quota
                print("⚠️ API key is valid but rate limited")
                # Continue to save it anyway
            else:
                # Some other error - but key might still be valid
                print(f"⚠️ Test request failed but saving key anyway: {error_msg}")

    except Exception as e:
        print(f"⚠️ Could not validate API key, but saving anyway: {e}")
        # Don't block saving - the key might still be valid

    # Encrypt and save the key
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    try:
        encrypted_key = api_encryption.encrypt(api_key)
        cursor.execute('''
            UPDATE users SET scrapingbee_api_key = ? WHERE id = ?
        ''', (encrypted_key, current_user.id))

        conn.commit()

        flash('ScrapingBee API key saved successfully!', 'success')
        print(f"✅ API key saved for user {current_user.email}")

    except Exception as e:
        print(f"❌ Error saving API key: {e}")
        flash('Error saving API key. Please try again.', 'error')
    finally:
        conn.close()

    return redirect(url_for('settings'))

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
def add_target_category():
    """Add a new target category to an existing product"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be in JSON format'}), 400
        data = request.get_json()
        product_id = data.get('product_id')
        category_name = data.get('category_name')
        target_rank = data.get('target_rank', 1)
        email = data.get('email')

        if not all([product_id, category_name, email]):
            return jsonify({'error': 'Missing required fields'}), 400

        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        # Verify product belongs to user
        cursor.execute('''
            SELECT id FROM products 
            WHERE id = ? AND user_email = ?
        ''', (product_id, email))

        if not cursor.fetchone():
            return jsonify({'error': 'Product not found'}), 404

        # Add target category
        cursor.execute('''
            INSERT INTO target_categories (product_id, category_name, target_rank)
            VALUES (?, ?, ?)
        ''', (product_id, category_name, target_rank))

        conn.commit()
        conn.close()

        return jsonify({'status': 'Target category added successfully'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_target_categories/<int:product_id>')
def get_target_categories(product_id):
    """Get all target categories for a product"""
    email = request.args.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400

    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT tc.id, tc.category_name, tc.target_rank, tc.best_rank_achieved, 
               tc.is_achieved, tc.date_achieved
        FROM target_categories tc
        JOIN products p ON tc.product_id = p.id
        WHERE tc.product_id = ? AND p.user_email = ?
        ORDER BY tc.created_at DESC
    ''', (product_id, email))

    categories = []
    for row in cursor.fetchall():
        categories.append({
            'id': row[0],
            'category_name': row[1],
            'target_rank': row[2],
            'best_rank_achieved': row[3],
            'is_achieved': bool(row[4]),
            'date_achieved': row[5]
        })

    conn.close()

    return jsonify(categories)

@app.route('/check_products')
def manual_check():
    """Manual trigger for checking all products"""
    try:
        check_all_products()
        return jsonify({'status': 'Products checked successfully'})
    except Exception as e:
        print(f"❌ Manual check failed: {e}")
        return jsonify({'error': 'Failed to check products', 'details': str(e)}), 500

@app.route('/toggle_monitoring/<int:product_id>')
def toggle_monitoring(product_id):
    """Toggle monitoring status for a product"""
    try:
        email = request.args.get('email')
        if not email:
            return jsonify({'error': 'Email required'}), 400

        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        # Verify the product belongs to the user
        cursor.execute('''
            SELECT active FROM products 
            WHERE id = ? AND user_email = ?
        ''', (product_id, email))

        result = cursor.fetchone()
        if not result:
            return jsonify({'error': 'Product not found'}), 404

        # Toggle the active status
        new_status = 0 if result[0] else 1
        cursor.execute('''
            UPDATE products 
            SET active = ? 
            WHERE id = ? AND user_email = ?
        ''', (new_status, product_id, email))

        conn.commit()
        conn.close()

        status_text = 'resumed' if new_status else 'paused'
        return jsonify({'status': f'Monitoring {status_text} successfully'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

@app.route('/delete_product/<int:product_id>')
def delete_product(product_id):
    """Permanently delete a product and all its data"""
    try:
        email = request.args.get('email')
        if not email:
            return jsonify({'error': 'Email required'}), 400

        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        # Verify the product belongs to the user
        cursor.execute('''
            SELECT id FROM products 
            WHERE id = ? AND user_email = ?
        ''', (product_id, email))

        if not cursor.fetchone():
            return jsonify({'error': 'Product not found'}), 404

        # Delete related records first (foreign key constraints)
        cursor.execute('DELETE FROM target_categories WHERE product_id = ?', (product_id,))
        cursor.execute('DELETE FROM bestseller_screenshots WHERE product_id = ?', (product_id,))
        cursor.execute('DELETE FROM rankings WHERE product_id = ?', (product_id,))
        cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))

        conn.commit()
        conn.close()

        return jsonify({'status': 'Product deleted successfully'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def check_all_products():
    """Check all active products - screenshots only on achievements after initial"""
    print("🔄 Starting scheduled product check...")
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Get products grouped by user with user_id
    cursor.execute('''
        SELECT p.id, p.product_url, p.product_title, p.user_id 
        FROM products p 
        JOIN users u ON p.user_id = u.id
        WHERE p.active = 1 
        ORDER BY p.user_id
    ''')
    products = cursor.fetchall()
    print(f"📊 Found {len(products)} active products to check")

    current_user_id = None
    user_monitor = None
    users_without_keys = set()

    for product_id, url, title, user_id in products:
        try:
            # Check if we need a new monitor instance for this user
            if user_id != current_user_id:
                current_user_id = user_id
                user_monitor = AmazonMonitor.for_user(user_id)

                if not user_monitor.api_key:
                    if user_id not in users_without_keys:
                        print(f"⚠️ User {user_id} has no API key configured - skipping their products")
                        users_without_keys.add(user_id)
                    continue

            if not user_monitor or not user_monitor.api_key:
                continue

            print(f"🔍 Checking product {product_id}: {title} (User: {user_id})")

            # Get previous rank to check if there's an improvement
            cursor.execute('''
                SELECT current_rank, current_category, is_bestseller 
                FROM products WHERE id = ?
            ''', (product_id,))
            previous_data = cursor.fetchone()
            previous_rank = int(previous_data[0]) if previous_data[0] else 999999
            was_bestseller = previous_data[2]

            # Scrape the page (screenshot will be captured automatically by ScrapingBee)
            result = user_monitor.scrape_amazon_page(url)

            if result['success']:
                print(f"✅ Successfully scraped product {product_id}")
                product_info = user_monitor.extract_product_info(result['html'])

                current_rank = int(product_info['rank']) if product_info['rank'] else None
                is_bestseller_now = product_info['is_bestseller']

                # Update product info
                cursor.execute('''
                    UPDATE products 
                    SET current_rank = ?, current_category = ?, is_bestseller = ?, last_checked = ?
                    WHERE id = ?
                ''', (
                    product_info['rank'], product_info['category'], 
                    is_bestseller_now, datetime.now(), product_id
                ))

                # Add ranking record
                cursor.execute('''
                    INSERT INTO rankings (product_id, rank_number, category, is_bestseller, checked_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    product_id, current_rank,
                    product_info['category'], is_bestseller_now, datetime.now()
                ))

                # Determine if we should save a screenshot
                should_save_screenshot = False
                achievement_reason = ""

                # Check for new bestseller status
                if is_bestseller_now and not was_bestseller:
                    should_save_screenshot = True
                    achievement_reason = "New Bestseller!"
                    print(f"🏆 New bestseller achievement for product {product_id}!")

                # Check for significant rank improvement (e.g., entering top 10)
                if current_rank:
                    if current_rank <= 10 and previous_rank > 10:
                        should_save_screenshot = True
                        achievement_reason = f"Entered Top 10! (#{current_rank})"
                        print(f"🎯 Product {product_id} entered top 10!")
                    elif current_rank == 1 and previous_rank != 1:
                        should_save_screenshot = True
                        achievement_reason = "Reached #1!"
                        print(f"🥇 Product {product_id} reached #1!")

                # Check target categories
                if product_info['rank'] and product_info['category']:
                    achievements = user_monitor.check_category_achievements(
                        product_id, 
                        product_info, 
                        product_info['rank'], 
                        product_info['category']
                    )

                    if achievements:
                        should_save_screenshot = True
                        achievement_reason = f"Target achieved in {achievements[0]['category']}"

                # Save screenshot only if there's an achievement
                if should_save_screenshot and result.get('screenshot'):
                    print(f"📸 Saving achievement screenshot: {achievement_reason}")
                    cursor.execute('''
                        INSERT INTO bestseller_screenshots 
                        (product_id, screenshot_data, rank_achieved, category, achieved_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        product_id, result['screenshot'], 
                        product_info['rank'], 
                        f"{product_info['category']} - {achievement_reason}", 
                        datetime.now()
                    ))

                    # Send email notification if configured
                    cursor.execute('SELECT email FROM users WHERE id = ?', (user_id,))
                    user_email = cursor.fetchone()[0]

                    if email_notifier.is_configured():
                        print(f"📧 Sending achievement notification to {user_email}")
                        product_info['achievement_reason'] = achievement_reason
                        email_notifier.send_bestseller_notification(
                            user_email, 
                            product_info, 
                            result['screenshot'],
                            achievement_type=achievement_reason
                        )
                else:
                    print(f"📈 Product {product_id} rank: {current_rank} - no achievement triggers")
            else:
                print(f"❌ Failed to scrape product {product_id}: {result.get('error', 'Unknown error')}")

            # Rate limiting
            print("⏳ Waiting 2 seconds before next request...")
            time.sleep(2)

        except Exception as e:
            print(f"❌ Error checking product {product_id}: {e}")
            import traceback
            traceback.print_exc()
            continue

    conn.commit()
    conn.close()
    print("✅ Scheduled product check complete")
    print(f"📊 Skipped products from {len(users_without_keys)} users without API keys")

# Scheduler for automatic checking
def run_scheduler():
    schedule.every(60).minutes.do(check_all_products)  # Check every 60 minutes

    while True:
        schedule.run_pending()
        time.sleep(60)

# Start scheduler in background
scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()

if __name__ == '__main__':
    # Get port from environment (Railway sets this automatically)
    port = int(os.environ.get('PORT', 5000))

    print("🚀 Starting Amazon Bestseller Monitor...")

    # Check database connection
    if os.environ.get('DATABASE_URL'):
        print("✅ PostgreSQL database configured")
    else:
        print("⚠️ Using SQLite for development")

    # Check API key
    if SCRAPINGBEE_API_KEY:
        print("✅ ScrapingBee API key loaded")
    else:
        print("❌ ScrapingBee API key not configured")

    # Check email configuration
    if email_notifier.is_configured():
        print("✅ Email notifications configured")
    else:
        print("⚠️ Email notifications not configured")

    # Production vs Development settings
    is_production = os.environ.get('RAILWAY_ENVIRONMENT') is not None
    debug_mode = not is_production

    print(f"🌍 Environment: {'Production' if is_production else 'Development'}")

    # Start the application
    if is_production:
        # Let gunicorn handle this in production
        app.run(debug=False, host='0.0.0.0', port=port)
    else:
        # Development mode
        app.run(debug=True, host='0.0.0.0', port=port)