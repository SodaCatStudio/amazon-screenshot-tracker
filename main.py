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

SCHEDULER_ENABLED = os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true'
if SCHEDULER_ENABLED:
    print("⚠️ SCHEDULER ENABLED - Will check products every 60 minutes")
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
else:
    print("✅ SCHEDULER DISABLED - No automatic checks will occur")
    print("To enable: Set ENABLE_SCHEDULER=true in environment variables")

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
def create_app():
    """Application factory pattern for better WSGI compatibility"""
    return app
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY must be set in environment variables!")

app.config['WTF_CSRF_ENABLED'] = True
#@app.before_request
#def log_request():
#    print(f"📍 Request: {request.method} {request.path}")
#    if current_user.is_authenticated:
#        print(f"   User: {current_user.email}")
 #   else:
#        print("   User: Anonymous")

# Create authentication blueprint for better organization
auth = Blueprint('auth', __name__)

# Initialize Flask-Login with security settings
login_manager = LoginManager()

csrf = CSRFProtect()

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],  # Increased from 50/day, 10/hour
    storage_uri="memory://",  # Use in-memory storage
    strategy="fixed-window"
)

login_manager.login_view = 'auth.login'  # type: ignore
login_manager.login_message = 'Please log in to access this page.'
login_manager.session_protection = 'strong'  # Protect against session hijacking

login_manager.init_app(app)
csrf.init_app(app)
limiter.init_app(app)

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
if os.environ.get('FLASK_ENV') == 'production':
    # Railway-friendly Talisman configuration
    talisman_config = {
        'force_https': False,  # Railway terminates HTTPS
        'strict_transport_security': False,  # Railway handles this
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
                diagnostics.append(f"❌ Failed to send test email")

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

@app.route('/health')
def health_check():
    """Ultra-simple health check that can't fail"""
    return "OK"  # Just return plain text, no templates, no database, nothing

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
    """Handle all email notifications for the application with timeout protection"""
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.username = SMTP_USERNAME
        self.password = SMTP_PASSWORD
        self.sender_email = SENDER_EMAIL
        self.sender_name = SENDER_NAME
        self.timeout = 10  # 10 second timeout for SMTP operations

    def is_configured(self):
        """Check if email settings are configured"""
        return all([self.smtp_server, self.username, self.password])

    def send_email(self, recipient, subject, html_content, attachments=None):
        """Generic email sending method with timeout protection"""
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

            # Send email with timeout
            import socket
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.timeout)

            try:
                with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=self.timeout) as server:
                    server.starttls()
                    if not self.username or not self.password:
                        raise ValueError("SMTP username or password is not configured")
                    server.login(self.username, self.password)
                    server.send_message(msg)

                print(f"✅ Email sent successfully to {recipient}")
                return True

            finally:
                socket.setdefaulttimeout(original_timeout)

        except smtplib.SMTPServerDisconnected:
            print(f"❌ SMTP server disconnected while sending to {recipient}")
            return False
        except smtplib.SMTPConnectError:
            print(f"❌ Could not connect to SMTP server")
            return False
        except socket.timeout:
            print(f"❌ Email sending timed out after {self.timeout} seconds")
            return False
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
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

def get_db_type():
    """Determine if using PostgreSQL or SQLite"""
    return 'postgresql' if os.environ.get('DATABASE_URL') else 'sqlite'

class DatabaseManager:
    def __init__(self):
        # Only initialize if tables don't exist
        self.init_db_if_needed()

    def get_db_type(self):
        """Determine if using PostgreSQL or SQLite"""
        return 'postgresql' if os.environ.get('DATABASE_URL') else 'sqlite'

    def init_db_if_needed(self):
        """Only create tables if they don't exist - preserve data"""
        print(f"🔧 Checking database state...")
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

                # FIX: Handle RealDictCursor returning dict-like object
                if isinstance(result, dict):
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
            cursor.execute(f"""
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

    def add_column_if_not_exists(self, cursor, table_name, column_name, column_type):
        """Safely add column if it doesn't exist"""
        try:
            cursor.execute(f"""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = %s AND column_name = %s
            """, (table_name, column_name))

            if not cursor.fetchone():
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                print(f"✅ Added column {column_name} to {table_name}")
            else:
                print(f"✅ Column {column_name} already exists in {table_name}")
        except Exception as e:
            print(f"⚠️ Error adding column {column_name}: {e}")

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
    """Enhanced User model with proper initialization"""
    def __init__(self, id, email, full_name=None, is_verified=False, is_active=True):
        self.id = id  # Make sure ID is set!
        self.email = email
        self.full_name = full_name
        self.is_verified = is_verified
        self._is_active = is_active  # Use private variable to avoid conflict
        
    def get_id(self):
        """Return the user ID as a string for Fla"""
        return str(self.id)
    
    @property
    def is_active(self):
        """Override is_active property"""
        return self._is_active
    
    @is_active.setter
    def is_active(self, value):
        self._is_active = value

    def __repr__(self):
        return f'<User {self.email}>'

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

# Authentication routes with best practices
@auth.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with validation - FIXED for PostgreSQL"""
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

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Check if user exists
            if get_db_type() == 'postgresql':
                cursor.execute('SELECT id FROM users WHERE LOWER(email) = LOWER(%s)', (email,))
            else:
                cursor.execute('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', (email,))

            if cursor.fetchone():
                flash('An account with this email already exists', 'error')
                return render_template('auth/register.html')

            # Create user with secure password hash
            password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            verification_token = secrets.token_urlsafe(32)
            token_expiry = datetime.now() + timedelta(hours=24)

            if get_db_type() == 'postgresql':
                cursor.execute('''
                    INSERT INTO users (email, password_hash, full_name, verification_token, verification_token_expiry)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                ''', (email, password_hash, full_name, verification_token, token_expiry))

                result = cursor.fetchone()
                user_id = result['id'] if isinstance(result, dict) else result[0]
            else:
                cursor.execute('''
                    INSERT INTO users (email, password_hash, full_name, verification_token, verification_token_expiry)
                    VALUES (?, ?, ?, ?, ?)
                ''', (email, password_hash, full_name, verification_token, token_expiry))
                user_id = cursor.lastrowid

            # Store verification token
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    INSERT INTO email_verifications (user_id, token)
                    VALUES (%s, %s)
                ''', (user_id, verification_token))
            else:
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
                if get_db_type() == 'postgresql':
                    cursor.execute('UPDATE users SET is_verified = true WHERE id = %s', (user_id,))
                else:
                    cursor.execute('UPDATE users SET is_verified = 1 WHERE id = ?', (user_id,))
                conn.commit()
                flash('Registration successful! You can now log in.', 'success')

            return redirect(url_for('auth.login'))

        except Exception as e:
            conn.rollback()
            print(f"Registration error: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred during registration. Please try again.', 'error')
        finally:
            conn.close()

    return render_template('auth/register.html')

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
                    print(f"✅ Verification email sent successfully")
                    flash('Verification email sent! Please check your inbox.', 'success')
                else:
                    print(f"❌ Failed to send verification email")
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

@app.route('/debug/products')
def debug_products():
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Check products table
        cursor.execute('SELECT COUNT(*) FROM products')
        total_products = cursor.fetchone()[0]

        # Check products for current user
        cursor.execute('SELECT COUNT(*) FROM products WHERE user_id = %s OR user_email = %s', 
                       (current_user.id, current_user.email))
        user_products = cursor.fetchone()[0]

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
        count = cursor.fetchone()[0]

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
            if 'scheduler_thread' in globals() and scheduler_thread.is_alive():
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
    """Find where credits are leaking - FIXED"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Check for any orphaned active products
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT COUNT(*) as orphaned
                FROM products p
                LEFT JOIN users u ON p.user_id = u.id
                WHERE u.id IS NULL AND p.active = true
            ''')
        else:
            cursor.execute('''
                SELECT COUNT(*) as orphaned
                FROM products p
                LEFT JOIN users u ON p.user_id = u.id
                WHERE u.id IS NULL AND p.active = 1
            ''')

        orphaned = cursor.fetchone()
        # FIX: Handle dict/tuple properly
        if orphaned:
            if isinstance(orphaned, dict):
                orphaned_count = orphaned.get('orphaned', 0)
            else:
                orphaned_count = orphaned[0] if orphaned else 0
        else:
            orphaned_count = 0

        # Check ALL products regardless of user
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN active = true THEN 1 ELSE 0 END) as active_count
                FROM products
            ''')
        else:
            cursor.execute('''
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active_count
                FROM products
            ''')

        all_products = cursor.fetchone()
        if isinstance(all_products, dict):
            total_products = all_products.get('total', 0)
            total_active = all_products.get('active_count', 0)
        else:
            total_products = all_products[0] if all_products else 0
            total_active = all_products[1] if all_products and all_products[1] else 0

        # Check rankings in last 24 hours - HOURLY BREAKDOWN
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT 
                    DATE_TRUNC('hour', r.checked_at) as check_hour,
                    COUNT(*) as checks_made,
                    COUNT(DISTINCT p.id) as unique_products
                FROM rankings r
                JOIN products p ON r.product_id = p.id
                WHERE r.checked_at > %s
                GROUP BY DATE_TRUNC('hour', r.checked_at)
                ORDER BY check_hour DESC
                LIMIT 24
            ''', (datetime.now() - timedelta(hours=24),))
        else:
            cursor.execute('''
                SELECT 
                    strftime('%Y-%m-%d %H:00:00', r.checked_at) as check_hour,
                    COUNT(*) as checks_made,
                    COUNT(DISTINCT p.id) as unique_products
                FROM rankings r
                JOIN products p ON r.product_id = p.id
                WHERE r.checked_at > ?
                GROUP BY strftime('%Y-%m-%d %H:00:00', r.checked_at)
                ORDER BY check_hour DESC
                LIMIT 24
            ''', (datetime.now() - timedelta(hours=24),))

        hourly_usage = cursor.fetchall()

        # Check if scheduler is running
        global scheduler_thread
        scheduler_running = False
        try:
            scheduler_running = 'scheduler_thread' in globals() and scheduler_thread.is_alive()
        except:
            pass

        # Check scheduled jobs
        import schedule
        scheduled_jobs = len(schedule.jobs)

        # Get most recent checks
        if get_db_type() == 'postgresql':
            cursor.execute('''
                SELECT r.checked_at, p.product_title, p.user_id, p.active
                FROM rankings r
                JOIN products p ON r.product_id = p.id
                ORDER BY r.checked_at DESC
                LIMIT 10
            ''')
        else:
            cursor.execute('''
                SELECT r.checked_at, p.product_title, p.user_id, p.active
                FROM rankings r
                JOIN products p ON r.product_id = p.id
                ORDER BY r.checked_at DESC
                LIMIT 10
            ''')

        recent_checks = cursor.fetchall()

        conn.close()

        # Calculate if there's suspicious activity
        suspicious_activity = False
        suspicious_reasons = []

        if total_active > 0 and total_products == 0:
            suspicious_activity = True
            suspicious_reasons.append("Active products exist but no products in database!")

        if orphaned_count > 0:
            suspicious_activity = True
            suspicious_reasons.append(f"{orphaned_count} orphaned active products found!")

        # Check for multiple checks per hour
        for hour_data in hourly_usage:
            if isinstance(hour_data, dict):
                checks = hour_data.get('checks_made', 0)
                products = hour_data.get('unique_products', 0)
            else:
                checks = hour_data[1] if len(hour_data) > 1 else 0
                products = hour_data[2] if len(hour_data) > 2 else 0

            if products > 0 and checks > products * 2:  # More than 2 checks per product per hour
                suspicious_activity = True
                suspicious_reasons.append(f"Multiple checks per product in same hour: {checks} checks for {products} products")
                break

        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; }}
                .danger {{ background: #f8d7da; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                .warning {{ background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                .success {{ background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background: #f5f5f5; }}
                .suspicious {{ background: #ffcccc; }}
            </style>
        </head>
        <body>
            <h1>🔍 Credit Leak Detector</h1>
        """

        if suspicious_activity:
            html += f"""
            <div class="danger">
                <h2>⚠️ SUSPICIOUS ACTIVITY DETECTED!</h2>
                <ul>
                    {''.join([f'<li>{reason}</li>' for reason in suspicious_reasons])}
                </ul>
            </div>
            """

        html += f"""
            <div class="{'danger' if scheduler_running else 'success'}">
                <h2>Scheduler Status</h2>
                <p><strong>Thread Alive:</strong> {'🔴 YES - RUNNING!' if scheduler_running else '🟢 NO - Stopped'}</p>
                <p><strong>Scheduled Jobs:</strong> {scheduled_jobs}</p>
                <p><strong>ENABLE_SCHEDULER env:</strong> {os.environ.get('ENABLE_SCHEDULER', 'Not Set')}</p>
            </div>

            <div class="warning">
                <h2>System Statistics</h2>
                <p><strong>Total Products (all users):</strong> {total_products}</p>
                <p><strong>Active Products (all users):</strong> {total_active}</p>
                <p><strong>Orphaned Active Products:</strong> {orphaned_count}</p>
            </div>

            <h2>Hourly Usage (Last 24 Hours)</h2>
            <p>If you see multiple entries per hour, the scheduler is running too frequently!</p>
            <table>
                <tr>
                    <th>Hour</th>
                    <th>API Calls</th>
                    <th>Unique Products</th>
                    <th>Status</th>
                </tr>
        """

        for hour in hourly_usage:
            if isinstance(hour, dict):
                time = hour.get('check_hour', '')
                checks = hour.get('checks_made', 0)
                products = hour.get('unique_products', 0)
            else:
                time = hour[0] if hour else ''
                checks = hour[1] if len(hour) > 1 else 0
                products = hour[2] if len(hour) > 2 else 0

            is_suspicious = checks > products * 2 if products > 0 else False
            row_class = 'suspicious' if is_suspicious else ''
            status = '⚠️ MULTIPLE CHECKS!' if is_suspicious else 'Normal'

            html += f"""
                <tr class="{row_class}">
                    <td>{time}</td>
                    <td><strong>{checks}</strong></td>
                    <td>{products}</td>
                    <td>{status}</td>
                </tr>
            """

        html += """
            </table>

            <h2>Most Recent Checks</h2>
            <table>
                <tr>
                    <th>Time</th>
                    <th>Product</th>
                    <th>User ID</th>
                    <th>Was Active?</th>
                </tr>
        """

        for check in recent_checks:
            if isinstance(check, dict):
                time = check.get('checked_at', '')
                title = check.get('product_title', '')
                user_id = check.get('user_id', '')
                active = check.get('active', False)
            else:
                time = check[0] if check else ''
                title = check[1] if len(check) > 1 else ''
                user_id = check[2] if len(check) > 2 else ''
                active = check[3] if len(check) > 3 else False

            html += f"""
                <tr>
                    <td>{time}</td>
                    <td>{title[:30]}...</td>
                    <td>{user_id}</td>
                    <td>{'Yes' if active else 'No'}</td>
                </tr>
            """

        html += f"""
            </table>

            <h2>🚨 Emergency Actions</h2>
            <a href="/kill_scheduler" 
               onclick="return confirm('This will attempt to stop the scheduler. Continue?')"
               style="background: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px;">
                🛑 KILL SCHEDULER
            </a>

            <br><br>
            <a href="/dashboard">Dashboard</a> | 
            <a href="/scrapingbee_audit">Full Audit</a>
        </body>
        </html>
        """

        return html

    except Exception as e:
        if conn:
            conn.close()
        import traceback
        return f"<pre>{traceback.format_exc()}</pre>", 500


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

        return f"""
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
        return f"Error: {str(e)}", 500

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
        self.api_key = api_key or SCRAPINGBEE_API_KEY

    @classmethod
    def for_user(cls, user_id):
        """Create monitor instance with user's API key"""
        conn = get_db()
        cursor = conn.cursor()

        try:
            if get_db_type() == 'postgresql':
                cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (user_id,))
            else:
                cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (user_id,))

            result = cursor.fetchone()

            if result:
                if isinstance(result, dict):
                    encrypted_key = result.get('scrapingbee_api_key')
                else:
                    encrypted_key = result[0] if result else None
            else:
                encrypted_key = None

            conn.close()

            if encrypted_key:
                try:
                    decrypted_key = api_encryption.decrypt(encrypted_key)
                    print(f"✅ Using user-specific API key for user {user_id}")
                    return cls(decrypted_key)
                except Exception as e:
                    print(f"❌ Error decrypting API key for user {user_id}: {e}")

            print(f"⚠️ No user-specific API key found for user {user_id}. Using system default.")
            return cls()

        except Exception as e:
            print(f"❌ Error retrieving API key for user {user_id}: {e}")
            if conn:
                conn.close()
            return cls()
    
    def scrape_amazon_page(self, url):
        """Use ScrapingBee to scrape Amazon page and take screenshot - FULLY FIXED"""
        if not self.api_key:
            print("❌ ScrapingBee API key not configured")
            return {'success': False, 'error': 'ScrapingBee API key not configured', 'html': '', 'screenshot': None}

        try:
            print(f"🔄 Starting ScrapingBee request for: {url}")
            print(f"🔑 Using API key: {self.api_key[:10]}...")

            # Use json_response to get both HTML and screenshot
            params = {
                'api_key': self.api_key,
                'url': url,
                'render_js': 'true',  # Required for screenshots
                'screenshot': 'true',  # Enable screenshot
                'json_response': 'true',  # Get JSON response with both HTML and screenshot
                'screenshot_full_page': 'false',
                'wait': '3000',
                'premium_proxy': 'true',
                'country_code': 'us',
            }

            print("📤 Making request to ScrapingBee with screenshot enabled...")
            response = requests.get(SCRAPINGBEE_URL, params=params, timeout=60)

            print(f"📥 ScrapingBee response status: {response.status_code}")

            if response.status_code == 200:
                print("✅ ScrapingBee request successful")

                try:
                    # With json_response=true, we get a JSON object
                    response_data = response.json()

                    html_content = response_data.get('body', '')
                    screenshot_data = response_data.get('screenshot', '')

                    print(f"📄 HTML content length: {len(html_content) if html_content else 0} characters")
                    print(f"📸 Screenshot data present: {'Yes' if screenshot_data else 'No'}")

                    if screenshot_data:
                        print(f"📸 Screenshot size: {len(screenshot_data)} characters")
                        # The screenshot is already base64 encoded
                        if not screenshot_data.startswith('data:'):
                            # Ensure it's just the base64 data, no data URI prefix
                            screenshot_data = screenshot_data.replace('data:image/png;base64,', '')

                    return {
                        'html': html_content or '',
                        'screenshot': screenshot_data if screenshot_data else None,
                        'success': True
                    }

                except json.JSONDecodeError as e:
                    print(f"⚠️ JSON decode error, trying alternative method: {e}")
                    # Fallback to non-JSON response
                    return {
                        'html': response.text,
                        'screenshot': response.headers.get('Spb-Screenshot'),
                        'success': True
                    }

            else:
                error_msg = f'HTTP {response.status_code}: {response.text[:500]}'
                print(f"❌ ScrapingBee error: {error_msg}")

                # Check for specific errors
                if response.status_code == 401:
                    error_msg = "Invalid API key. Please check your ScrapingBee API key."
                elif response.status_code == 429:
                    error_msg = "Rate limit reached. Please wait and try again."
                elif response.status_code == 402:
                    error_msg = "Insufficient credits. Please check your ScrapingBee account."

                return {'success': False, 'error': error_msg, 'html': '', 'screenshot': None}

        except requests.exceptions.Timeout:
            error_msg = 'ScrapingBee request timed out (60s)'
            print(f"⏰ {error_msg}")
            return {'success': False, 'error': error_msg, 'html': '', 'screenshot': None}
        except Exception as e:
            error_msg = f'ScrapingBee request failed: {str(e)}'
            print(f"💥 {error_msg}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': error_msg, 'html': '', 'screenshot': None}

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

            # Extract title - multiple methods
            title_selectors = [
                ('span', {'id': 'productTitle'}),
                ('h1', {'id': 'title'}),
                ('h1', {'class': 'a-size-large'}),
                ('span', {'class': 'a-size-large product-title-word-break'})
            ]

            for tag, attrs in title_selectors:
                title_element = soup.find(tag, attrs)
                if title_element:
                    product_info['title'] = ' '.join(title_element.stripped_strings)
                    print(f"📋 Found title: {product_info['title'][:100]}...")
                    break

            if not product_info['title']:
                # Try meta tags
                meta_title = soup.find('meta', {'property': 'og:title'})
                if meta_title and meta_title.get('content'):
                    product_info['title'] = meta_title['content']
                    print(f"📋 Found title in meta: {product_info['title'][:100]}...")
                else:
                    product_info['title'] = 'Unknown Product'
                    print("⚠️ Could not find product title")

            # Look for bestseller badges
            print("🔍 Searching for bestseller indicators...")

            # Check for bestseller badges
            badge_patterns = [
                'best seller',
                'best-seller', 
                'bestseller',
                '#1 best seller',
                'amazon\'s choice'
            ]

            for element in soup.find_all(['span', 'div', 'a'], class_=lambda x: x and 'badge' in x.lower()):
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
                    if elem and elem.strip():
                        match = re.search(r'#([\d,]+)\s+in\s+([^(\n]+)', elem)
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

# Initialize components
db_manager = DatabaseManager()
monitor = AmazonMonitor(SCRAPINGBEE_API_KEY)

@app.route('/')
def index():
    """Landing page - properly handle authenticated users"""
    print(f"🔍 INDEX: Route called")

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
                ''', (product_id, scrape_result['screenshot'], 
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
@limiter.limit("10 per minute")
@login_required
def add_product():
    """Fixed add_product with target categories and better error handling"""
    print(f"🔍 Adding product for user {current_user.email} (ID: {current_user.id})")

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Validate API key exists
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

        if not api_key:
            flash('Please add your ScrapingBee API key in settings.', 'error')
            conn.close()
            return redirect(url_for('settings'))

        url = request.form.get('url', '').strip()
        target_categories_input = request.form.get('target_categories', '').strip()

        if not url or 'amazon.' not in url.lower():
            flash('Please provide a valid Amazon product URL', 'error')
            conn.close()
            return redirect(url_for('add_product_form'))

        print(f"📦 Scraping product: {url}")

        # Scrape product
        try:
            user_monitor = AmazonMonitor.for_user(current_user.id)
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
            product_id = result['id'] if isinstance(result, dict) else result[0]
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

        print(f"✅ Product saved with ID: {product_id}")

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

        # Save baseline screenshot if available
        if scrape_result.get('screenshot'):
            print(f"📸 Saving baseline screenshot (length: {len(scrape_result['screenshot'])})")

            if get_db_type() == 'postgresql':
                cursor.execute('''
                    INSERT INTO baseline_screenshots 
                    (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (product_id) DO UPDATE SET
                    screenshot_data = EXCLUDED.screenshot_data,
                    captured_at = EXCLUDED.captured_at
                ''', (product_id, scrape_result['screenshot'], product_info.get('rank'),
                      product_info.get('category'), datetime.now()))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO baseline_screenshots 
                    (product_id, screenshot_data, initial_rank, initial_category, captured_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (product_id, scrape_result['screenshot'], product_info.get('rank'),
                      product_info.get('category'), datetime.now()))

            print("✅ Baseline screenshot saved")
        else:
            print("⚠️ No screenshot data to save")

        conn.commit()
        conn.close()

        flash(f'✅ Successfully added "{product_info.get("title", "Product")[:50]}..."', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        conn.rollback()
        print(f"❌ Error adding product: {e}")
        import traceback
        traceback.print_exc()

        if "Too Many Requests" in str(e):
            flash('Rate limit reached. Please wait a moment and try again.', 'warning')
        else:
            flash('Error adding product. Please try again.', 'error')

        conn.close()
        return redirect(url_for('add_product_form'))

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


# Add error handler for rate limit exceeded
@app.errorhandler(429)
def rate_limit_handler(e):
    """Handle rate limit exceeded errors"""
    flash('Rate limit exceeded. Please wait a moment and try again.', 'warning')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/check_scrapingbee_usage')
@login_required
def check_scrapingbee_usage():
    """Check ScrapingBee API key validity and usage"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get user's API key
        if get_db_type() == 'postgresql':
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (current_user.id,))
        else:
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (current_user.id,))

        result = cursor.fetchone()

        if result:
            if isinstance(result, dict):
                encrypted_key = result.get('scrapingbee_api_key')
            else:
                encrypted_key = result[0] if result else None
        else:
            encrypted_key = None

        conn.close()

        if not encrypted_key:
            return """
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>No API Key Found</h2>
                <p>Please add your ScrapingBee API key in settings first.</p>
                <a href="/settings">Go to Settings</a>
            </body>
            </html>
            """

        # Decrypt the API key
        try:
            api_key = api_encryption.decrypt(encrypted_key)
        except Exception as e:
            return f"Error decrypting API key: {str(e)}", 500

        # Test the API key with ScrapingBee's account endpoint
        import requests

        try:
            # ScrapingBee account info endpoint
            response = requests.get(
                'https://app.scrapingbee.com/api/v1/usage',
                params={'api_key': api_key},
                timeout=10
            )

            if response.status_code == 200:
                usage_data = response.json()

                return f"""
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; padding: 20px; }}
                        .success {{ color: green; }}
                        .warning {{ color: orange; }}
                        .error {{ color: red; }}
                        .usage-box {{ 
                            background: #f5f5f5; 
                            padding: 20px; 
                            border-radius: 8px; 
                            margin: 20px 0;
                        }}
                    </style>
                </head>
                <body>
                    <h2 class="success">✅ API Key is Valid!</h2>

                    <div class="usage-box">
                        <h3>ScrapingBee Usage</h3>
                        <p><strong>API Credits Used:</strong> {usage_data.get('used_credits', 'N/A')}</p>
                        <p><strong>Max API Credits:</strong> {usage_data.get('max_credits', 'N/A')}</p>
                        <p><strong>Credits Remaining:</strong> {usage_data.get('max_credits', 0) - usage_data.get('used_credits', 0)}</p>
                        <p><strong>Plan:</strong> {usage_data.get('plan', 'N/A')}</p>
                    </div>

                    <p><strong>API Key (first 20 chars):</strong> {api_key[:20]}...</p>

                    <h3>Quick Actions</h3>
                    <ul>
                        <li><a href="/add_product_form">Add a Product</a></li>
                        <li><a href="/dashboard">Back to Dashboard</a></li>
                        <li><a href="/settings">Settings</a></li>
                    </ul>
                </body>
                </html>
                """
            elif response.status_code == 401:
                return f"""
                <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2 class="error">❌ Invalid API Key</h2>
                    <p>The API key is not recognized by ScrapingBee.</p>
                    <p>Response: {response.text}</p>
                    <p><strong>API Key (first 20 chars):</strong> {api_key[:20]}...</p>
                    <br>
                    <p>Please check your API key in your ScrapingBee dashboard and update it in settings.</p>
                    <a href="/settings">Go to Settings</a>
                </body>
                </html>
                """
            elif response.status_code == 429:
                return """
                <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2 class="warning">⚠️ Rate Limited</h2>
                    <p>You've exceeded your ScrapingBee API rate limit.</p>
                    <p>Please wait a moment and try again.</p>
                    <a href="/dashboard">Back to Dashboard</a>
                </body>
                </html>
                """
            else:
                return f"""
                <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>API Check Result</h2>
                    <p><strong>Status Code:</strong> {response.status_code}</p>
                    <p><strong>Response:</strong> {response.text[:500]}</p>
                    <a href="/dashboard">Back to Dashboard</a>
                </body>
                </html>
                """

        except requests.exceptions.Timeout:
            return "ScrapingBee API check timed out", 504
        except Exception as e:
            return f"Error checking ScrapingBee API: {str(e)}", 500

    except Exception as e:
        if conn:
            conn.close()
        return f"Database error: {str(e)}", 500

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
    """Dashboard view - FIXED to match template expectations"""
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
            # Check for API key
            if get_db_type() == 'postgresql':
                cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (user_id,))
            else:
                cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (user_id,))

            result = cursor.fetchone()

            if result:
                if isinstance(result, dict):
                    api_key_value = result.get('scrapingbee_api_key')
                else:
                    api_key_value = result[0] if result else None

                has_api_key = bool(api_key_value)
            else:
                has_api_key = False

            print(f"📊 DASHBOARD_VIEW: User has API key: {has_api_key}")

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

            print(f"✅ DASHBOARD_VIEW: Rendering dashboard template")
            print(f"   Products format: {type(products)}, Screenshots format: {type(screenshots)}")

            # Render the dashboard template with the correct data format
            return render_template('dashboard.html',
                                 email=user_email,
                                 products=products,
                                 screenshots=screenshots,
                                 has_api_key=has_api_key)

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
    """User settings page - FIXED for PostgreSQL"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        if get_db_type() == 'postgresql':
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (current_user.id,))
        else:
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (current_user.id,))

        result = cursor.fetchone()

        # Fixed: Handle dict/tuple properly
        if result:
            if isinstance(result, dict):
                api_key_value = result.get('scrapingbee_api_key')
            else:
                api_key_value = result[0] if result else None
        else:
            api_key_value = None

        has_api_key = bool(api_key_value)

        print(f"⚙️ Settings page - User has API key: {has_api_key}")

    finally:
        conn.close()

    return render_template('settings.html', user=current_user, has_api_key=has_api_key)

@app.route('/update_api_key', methods=['POST'])
@login_required
def update_api_key():
    """Update user's ScrapingBee API key - FIXED for PostgreSQL"""
    api_key = request.form.get('api_key', '').strip()

    if not api_key:
        flash('API key cannot be empty', 'error')
        return redirect(url_for('settings'))

    # Basic validation of API key
    if len(api_key) < 20:
        flash('API key seems too short. Please check your ScrapingBee dashboard.', 'error')
        return redirect(url_for('settings'))

    print(f"🔑 Attempting to save API key for user {current_user.email} (ID: {current_user.id})")
    print(f"🔑 API key length: {len(api_key)}, starts with: {api_key[:10]}...")

    # Get database connection
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Encrypt the API key
        encrypted_key = api_encryption.encrypt(api_key)
        print(f"🔐 Encrypted key length: {len(encrypted_key)}")

        # Update in database - FIXED for PostgreSQL
        if get_db_type() == 'postgresql':
            cursor.execute('''
                UPDATE users 
                SET scrapingbee_api_key = %s 
                WHERE id = %s
            ''', (encrypted_key, current_user.id))
        else:
            cursor.execute('''
                UPDATE users 
                SET scrapingbee_api_key = ? 
                WHERE id = ?
            ''', (encrypted_key, current_user.id))

        # Check if update was successful
        if cursor.rowcount == 0:
            print(f"❌ No rows updated for user ID {current_user.id}")
            flash('Failed to save API key. User not found.', 'error')
            conn.rollback()
            conn.close()
            return redirect(url_for('settings'))

        # Commit the transaction
        conn.commit()
        print(f"✅ API key saved to database (affected rows: {cursor.rowcount})")

        # Verify it was actually saved
        if get_db_type() == 'postgresql':
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (current_user.id,))
        else:
            cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (current_user.id,))

        result = cursor.fetchone()
        if result:
            if isinstance(result, dict):
                saved_key = result.get('scrapingbee_api_key')
            else:
                saved_key = result[0] if result else None

            if saved_key:
                print(f"✅ Verification: API key is in database (length: {len(saved_key)})")
                flash('ScrapingBee API key saved successfully!', 'success')
            else:
                print(f"❌ Verification failed: API key not found in database after save")
                flash('API key save verification failed. Please try again.', 'error')
        else:
            print(f"❌ Could not verify saved API key")
            flash('API key saved but verification failed.', 'warning')

    except Exception as e:
        print(f"❌ Error saving API key: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
        flash('Error saving API key. Please try again.', 'error')
    finally:
        conn.close()

    return redirect(url_for('settings'))

@app.route('/test_api_key_save', methods=['GET', 'POST'])
@login_required
def test_api_key_save():
    """Test route to debug API key saving"""
    if request.method == 'POST':
        test_key = request.form.get('test_key', 'TEST_KEY_123456789012345678901234567890')

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Try to save directly without encryption first
            if get_db_type() == 'postgresql':
                cursor.execute('''
                    UPDATE users 
                    SET scrapingbee_api_key = %s 
                    WHERE id = %s
                ''', (test_key, current_user.id))
            else:
                cursor.execute('''
                    UPDATE users 
                    SET scrapingbee_api_key = ? 
                    WHERE id = ?
                ''', (test_key, current_user.id))

            conn.commit()

            # Check if it saved
            if get_db_type() == 'postgresql':
                cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = %s', (current_user.id,))
            else:
                cursor.execute('SELECT scrapingbee_api_key FROM users WHERE id = ?', (current_user.id,))

            result = cursor.fetchone()

            if result:
                if isinstance(result, dict):
                    saved_value = result.get('scrapingbee_api_key')
                else:
                    saved_value = result[0] if result else None
            else:
                saved_value = None

            conn.close()

            return f"""
            <html>
            <body style="font-family: monospace; padding: 20px;">
                <h2>API Key Save Test - Result</h2>
                <p><strong>Attempted to save:</strong> {test_key}</p>
                <p><strong>Rows affected:</strong> {cursor.rowcount}</p>
                <p><strong>Retrieved value:</strong> {saved_value}</p>
                <p><strong>Save successful:</strong> {saved_value == test_key}</p>
                <br>
                <a href="/test_api_key_save">Try Again</a> | 
                <a href="/check_api_key">Check API Key</a> | 
                <a href="/settings">Go to Settings</a>
            </body>
            </html>
            """

        except Exception as e:
            conn.rollback()
            conn.close()
            return f"Error: {str(e)}", 500

    # GET request - show form
    return """
    <html>
    <body style="font-family: monospace; padding: 20px;">
        <h2>Test API Key Saving</h2>
        <p>This will test saving a value directly to the database.</p>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="text" name="test_key" value="TEST_KEY_123456789012345678901234567890" size="50">
            <button type="submit">Save Test Key</button>
        </form>
        <br>
        <p><a href="/check_api_key">Check Current API Key</a></p>
    </body>
    </html>
    """

@app.route('/clear_api_key')
@login_required
def clear_api_key():
    """Clear the API key for debugging"""
    conn = get_db()
    cursor = conn.cursor()

    try:
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

        flash('API key cleared. Please add a new one.', 'info')
        return redirect(url_for('settings'))

    except Exception as e:
        conn.rollback()
        conn.close()
        flash(f'Error clearing API key: {str(e)}', 'error')
        return redirect(url_for('settings'))

@app.route('/test_encryption')
@login_required
def test_encryption():
    """Test the encryption/decryption system"""
    test_key = "TEST_API_KEY_1234567890"

    try:
        # Test encryption
        encrypted = api_encryption.encrypt(test_key)

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
            <p><strong>Encrypted:</strong> {encrypted[:50]}...</p>
            <p><strong>Encrypted Length:</strong> {len(encrypted)}</p>
            <p><strong>Decrypted:</strong> {decrypted}</p>
            <p><strong>Match:</strong> {decrypted == test_key}</p>

            <h3>2. Database Save/Retrieve Test</h3>
            <p><strong>Saved to DB:</strong> {encrypted[:50]}...</p>
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
@login_required
def toggle_monitoring(product_id):
    """Toggle monitoring status for a product - FIXED for authenticated users"""
    try:
        print(f"🔄 Toggle monitoring for product {product_id} by user {current_user.email}")

        conn = get_db()
        cursor = conn.cursor()

        # Verify the product belongs to the user
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

        # Get current status
        if isinstance(result, dict):
            current_status = result['active']
        else:
            current_status = result[0]

        # Toggle the active status
        new_status = 0 if current_status else 1

        if get_db_type() == 'postgresql':
            cursor.execute('''
                UPDATE products 
                SET active = %s 
                WHERE id = %s AND user_id = %s
            ''', (bool(new_status), product_id, current_user.id))
        else:
            cursor.execute('''
                UPDATE products 
                SET active = ? 
                WHERE id = ? AND user_id = ?
            ''', (new_status, product_id, current_user.id))

        conn.commit()
        conn.close()

        status_text = 'resumed' if new_status else 'paused'
        print(f"✅ Monitoring {status_text} for product {product_id}")
        return jsonify({'status': f'Monitoring {status_text} successfully'})

    except Exception as e:
        print(f"❌ Error toggling monitoring: {e}")
        if conn:
            conn.rollback()
            conn.close()
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
@login_required
def delete_product(product_id):
    """Permanently delete a product and all its data - FIXED for authenticated users"""
    try:
        print(f"🗑️ Delete request for product {product_id} by user {current_user.email}")

        conn = get_db()
        cursor = conn.cursor()

        # Verify the product belongs to the current user
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

        # Delete related records first (foreign key constraints)
        if get_db_type() == 'postgresql':
            cursor.execute('DELETE FROM target_categories WHERE product_id = %s', (product_id,))
            cursor.execute('DELETE FROM bestseller_screenshots WHERE product_id = %s', (product_id,))
            cursor.execute('DELETE FROM baseline_screenshots WHERE product_id = %s', (product_id,))
            cursor.execute('DELETE FROM rankings WHERE product_id = %s', (product_id,))
            cursor.execute('DELETE FROM products WHERE id = %s', (product_id,))
        else:
            cursor.execute('DELETE FROM target_categories WHERE product_id = ?', (product_id,))
            cursor.execute('DELETE FROM bestseller_screenshots WHERE product_id = ?', (product_id,))
            cursor.execute('DELETE FROM baseline_screenshots WHERE product_id = ?', (product_id,))
            cursor.execute('DELETE FROM rankings WHERE product_id = ?', (product_id,))
            cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))

        conn.commit()
        conn.close()

        print(f"✅ Product {product_id} deleted successfully")
        return jsonify({'status': 'Product deleted successfully'})

    except Exception as e:
        print(f"❌ Error deleting product: {e}")
        import traceback
        traceback.print_exc()
        if conn:
            conn.rollback()
            conn.close()
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
    # Only initialize DB if not in production with existing data
    db_manager = DatabaseManager()
    # Get port from environment (Railway sets this automatically)
    port = int(os.environ.get('PORT', 5000))
    is_production = os.environ.get('RAILWAY_ENVIRONMENT') is not None
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
        app.run(debug=False, host='0.0.0.0', port=port)
    else:
        app.run(debug=True, host='0.0.0.0', port=port)

if __name__ != '__main__':
    # For gunicorn
    print("🔧 Configuring app for gunicorn...")
    # Don't initialize database here