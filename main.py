# Amazon Bestseller Screenshot Monitor
# A web app to monitor Amazon products and capture bestseller screenshots

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
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

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-fallback-secret-key')

# Ensure correct initialization of LoginManager before setting properties
login_manager = LoginManager()
login_manager.init_app(app)

# Set login view correctly
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# ScrapingBee configuration - using environment variables for security
SCRAPINGBEE_API_KEY = os.environ.get('SCRAPINGBEE_SECRET_KEY')
SCRAPINGBEE_URL = 'https://app.scrapingbee.com/api/v1/'

# Validate that the API key is available
if not SCRAPINGBEE_API_KEY:
    print("⚠️  WARNING: SCRAPINGBEE_API_KEY environment variable not set!")
    print("Please add your ScrapingBee API key as a secret in Replit")
    print("Go to: Secrets tab → Add secret → Key: SCRAPINGBEE_API_KEY → Value: your_api_key")

class DatabaseManager:
    def __init__(self):
        self.init_db()
        self.add_target_categories_table()

    def init_db(self):
        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        # Products table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                product_url TEXT NOT NULL,
                product_title TEXT,
                current_rank TEXT,
                current_category TEXT,
                is_bestseller BOOLEAN DEFAULT 0,
                last_checked TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT 1
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

        conn.commit()
        conn.close()

    def add_target_categories_table(self):
        """Add table for tracking target categories per product"""
        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

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

        conn.commit()
        conn.close()
        print("✅ Target categories table ready!")

class AmazonMonitor:
    def __init__(self, api_key):
        self.api_key = api_key

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
    # Check if API key is configured
    if not SCRAPINGBEE_API_KEY:
        flash('ScrapingBee API key not configured. Please add SCRAPINGBEE_API_KEY to your secrets.', 'error')
    return render_template('index.html')

@app.route('/add_product', methods=['POST'])
def add_product():
    try:
        email = request.form.get('email')
        url = request.form.get('url')
        target_categories = request.form.get('target_categories', '')

        if not email or not url:
            flash('Email and URL are required!', 'error')
            return redirect(url_for('index'))

        # Validate URL
        if 'amazon.' not in url:
            flash('Please provide a valid Amazon product URL', 'error')
            return redirect(url_for('index'))

        # Initial scrape to get product info
        print("🔍 Starting initial scrape...")
        result = monitor.scrape_amazon_page(url)

        if not result['success']:
            error_msg = f'Error accessing product page: {result["error"]}'
            print(f"❌ {error_msg}")
            flash(error_msg, 'error')
            return redirect(url_for('index'))

        print("🔄 Extracting product information...")
        product_info = monitor.extract_product_info(result['html'])
        print(f"📊 Product info extracted: {product_info}")

        # Save to database
        conn = sqlite3.connect('amazon_monitor.db')
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO products (user_email, product_url, product_title, current_rank, 
                                current_category, is_bestseller, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            email, url, product_info['title'], product_info['rank'],
            product_info['category'], product_info['is_bestseller'], datetime.now()
        ))

        product_id = cursor.lastrowid
        print(f"💾 Saved product with ID: {product_id}")

        # Process target categories if provided
        if target_categories:
            categories = [cat.strip() for cat in target_categories.split(',') if cat.strip()]
            for category in categories:
                # Extract target rank if specified (e.g., "British Literature:5" means top 5)
                if ':' in category:
                    cat_name, target_rank = category.split(':', 1)
                    try:
                        target_rank = int(target_rank.strip())
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
            product_id, int(product_info['rank']) if product_info['rank'] else None,
            product_info['category'], product_info['is_bestseller'], datetime.now()
        ))

        # If it's already a bestseller, save screenshot
        if product_info['is_bestseller'] and result.get('screenshot'):
            print("🏆 Product is already a bestseller! Saving screenshot...")
            cursor.execute('''
                INSERT INTO bestseller_screenshots (product_id, screenshot_data, rank_achieved, 
                                                  category, achieved_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                product_id, result['screenshot'], product_info['rank'],
                product_info['category'], datetime.now()
            ))

        conn.commit()
        conn.close()

        success_msg = f'Product "{product_info["title"]}" added successfully!'
        print(f"✅ {success_msg}")
        flash(success_msg, 'success')
        return redirect(url_for('dashboard', email=email))

    except Exception as e:
        error_msg = f'Error adding product: {str(e)}'
        print(f"💥 {error_msg}")
        flash(error_msg, 'error')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    email = request.args.get('email')
    if not email:
        flash('Email required to view dashboard', 'error')
        return redirect(url_for('index'))

    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Get user's products with their active status
    cursor.execute('''
        SELECT id, product_title, current_rank, current_category, is_bestseller, 
               last_checked, created_at, active
        FROM products 
        WHERE user_email = ?
        ORDER BY created_at DESC
    ''', (email,))

    products = cursor.fetchall()

    # Get bestseller screenshots for user
    cursor.execute('''
        SELECT bs.id, p.product_title, bs.rank_achieved, bs.category, bs.achieved_at
        FROM bestseller_screenshots bs
        JOIN products p ON bs.product_id = p.id
        WHERE p.user_email = ?
        ORDER BY bs.achieved_at DESC
    ''', (email,))

    screenshots = cursor.fetchall()

    conn.close()

    return render_template('dashboard.html', email=email, products=products, screenshots=screenshots)

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
    """Check all active products for ranking changes"""
    print("🔄 Starting scheduled product check...")
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    # Fixed: Now selecting all three required columns
    cursor.execute('SELECT id, product_url, product_title FROM products WHERE active = 1')
    products = cursor.fetchall()
    print(f"📊 Found {len(products)} active products to check")

    for product_id, url, title in products:
        try:
            print(f"🔍 Checking product {product_id}: {title}")
            result = monitor.scrape_amazon_page(url)

            if result['success']:
                print(f"✅ Successfully scraped product {product_id}")
                product_info = monitor.extract_product_info(result['html'])

                # Update product info
                cursor.execute('''
                    UPDATE products 
                    SET current_rank = ?, current_category = ?, is_bestseller = ?, last_checked = ?
                    WHERE id = ?
                ''', (
                    product_info['rank'], product_info['category'], 
                    product_info['is_bestseller'], datetime.now(), product_id
                ))

                # Add ranking record
                cursor.execute('''
                    INSERT INTO rankings (product_id, rank_number, category, is_bestseller, checked_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    product_id, int(product_info['rank']) if product_info['rank'] else None,
                    product_info['category'], product_info['is_bestseller'], datetime.now()
                ))

                # Check for target category achievements
                if product_info['rank'] and product_info['category']:
                    achievements = monitor.check_category_achievements(
                        product_id, 
                        product_info, 
                        product_info['rank'], 
                        product_info['category']
                    )

                    # If any targets achieved and we have a screenshot, save it
                    if achievements and result.get('screenshot'):
                        for achievement in achievements:
                            print(f"🏆 Saving achievement screenshot for {achievement['category']}")
                            cursor.execute('''
                                INSERT INTO bestseller_screenshots 
                                (product_id, screenshot_data, rank_achieved, category, achieved_at)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (
                                product_id, result['screenshot'], 
                                achievement['rank'], achievement['category'], datetime.now()
                            ))

                            # Update the target category with screenshot ID
                            screenshot_id = cursor.lastrowid
                            cursor.execute('''
                                UPDATE target_categories 
                                SET screenshot_id = ? 
                                WHERE product_id = ? AND category_name = ?
                            ''', (screenshot_id, product_id, achievement['category']))

                # If newly achieved bestseller status, save screenshot
                if product_info['is_bestseller']:
                    # Check if we already have a recent bestseller screenshot
                    print(f"🏆 Product {product_id} is a bestseller!")
                    cursor.execute('''
                        SELECT id FROM bestseller_screenshots 
                        WHERE product_id = ? AND achieved_at > ?
                    ''', (product_id, datetime.now() - timedelta(hours=1)))

                    if not cursor.fetchone() and result.get('screenshot'):
                        print(f"📸 Saving new bestseller screenshot for product {product_id}")
                        cursor.execute('''
                            INSERT INTO bestseller_screenshots 
                            (product_id, screenshot_data, rank_achieved, category, achieved_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            product_id, result['screenshot'], product_info['rank'],
                            product_info['category'], datetime.now()
                        ))
                else:
                    print(f"📈 Product {product_id} rank: {product_info['rank']}")
            else:
                print(f"❌ Failed to scrape product {product_id}: {result.get('error', 'Unknown error')}")

            # Rate limiting - wait between requests
            print("⏳ Waiting 2 seconds before next request...")
            time.sleep(2)

        except Exception as e:
            print(f"❌ Error checking product {product_id}: {e}")
            # Continue with next product rather than failing entirely
            continue

    conn.commit()
    conn.close()
    print("✅ Scheduled product check complete")

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
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)

    print("🚀 Starting Amazon Bestseller Monitor...")

    # Check configuration
    if SCRAPINGBEE_API_KEY:
        print("✅ ScrapingBee API key loaded from environment")
    else:
        print("❌ ScrapingBee API key not found!")
        print("📝 To fix this in Replit:")
        print("   1. Click on 'Secrets' tab (🔒 icon)")
        print("   2. Add a new secret:")
        print("      Key: SCRAPINGBEE_API_KEY")
        print("      Value: your_actual_api_key_from_scrapingbee")
        print("   3. Restart the app")
        print()

    print("🌐 App will be available at your Replit URL")
    print("📊 Dashboard accessible with any email address")
    print("⏰ Products will be checked every 60 minutes")

    app.run(debug=True, host='0.0.0.0', port=5000)