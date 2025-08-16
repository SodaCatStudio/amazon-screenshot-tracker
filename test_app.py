# Copy ALL the imports from your main.py here
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
import psycopg2
from psycopg2.extras import RealDictCursor

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

# Just basic Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'test-key')

load_dotenv()
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

# All your environment variable assignments
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', SMTP_USERNAME)
SENDER_NAME = os.environ.get('SENDER_NAME', 'Amazon Screenshot Tracker')
SCRAPINGBEE_API_KEY = os.environ.get('SCRAPINGBEE_SECRET_KEY')
SCRAPINGBEE_URL = 'https://app.scrapingbee.com/api/v1/'

login_manager = LoginManager()
login_manager.init_app(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50 per day", "10 per hour"]
)

csrf = CSRFProtect()
csrf.init_app(app)

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
    def __init__(self, id, email, full_name=None, is_verified=False, is_active=True):
        self.id = id
        self.email = email
        self.full_name = full_name
        self.is_verified = is_verified
        self.is_active = is_active

    @staticmethod
    def get(user_id):
        # Your existing get method
        pass

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/health')
def health():
    return "OK", 200

@app.route('/')
def index():
    """Landing page - completely standalone"""
    print("🔍 INDEX: Standalone route called")

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Amazon Screenshot Tracker</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 50px; text-align: center; }
            .btn { padding: 15px 30px; background: #ff9900; color: white; text-decoration: none; border-radius: 5px; margin: 10px; }
        </style>
    </head>
    <body>
        <h1>🏆 Amazon Screenshot Tracker</h1>
        <p>Track your Amazon product rankings and capture achievement screenshots!</p>
        <a href="/auth/login" class="btn">Login</a>
        <a href="/auth/register" class="btn">Sign Up</a>
    </body>
    </html>
    """

    print("✅ INDEX: Returning standalone HTML")
    return html, 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)