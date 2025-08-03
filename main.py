from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
import sqlite3
import requests
from bs4 import BeautifulSoup
import base64
import io
from datetime import datetime, timedelta
import threading
import time
import schedule
import re
import os

app = Flask(__name__)
app.secret_key = 'SCRAPINGBEE_SECRET_KEY'

# ScrapingBee configuration
SCRAPINGBEE_API_KEY = os.environ.get('SCRAPINGBEE_SECRET_KEY')
SCRAPINGBEE_URL = 'https://app.scrapingbee.com/api/v1/'

if not SCRAPINGBEE_API_KEY:
    print("⚠️  WARNING: SCRAPINGBEE_API_KEY environment variable not set!")
    print("Please add your ScrapingBee API key as a secret in Replit")
    print("Go to: Secrets tab → Add secret → Key: SCRAPINGBEE_API_KEY → Value: your_api_key")

class DatabaseManager:
    def __init__(self):
        self.init_db()

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

class AmazonMonitor:
    def __init__(self, api_key):
        self.api_key = api_key

    def scrape_amazon_page(self, url):
        """Use ScrapingBee to scrape Amazon page and take screenshot"""
        if not self.api_key:
            return {'success': False, 'error': 'ScrapingBee API key not configured'}

        try:
            params = {
                'api_key': self.api_key,
                'url': url,
                'screenshot': 'true',
                'screenshot_full_page': 'true',
                'wait': '3000',  # Wait 3 seconds for page to load
                'premium_proxy': 'true',  # Use premium proxies for better success rate
                'country_code': 'us'
            }

            response = requests.get(SCRAPINGBEE_URL, params=params)

            if response.status_code == 200:
                # The response contains both HTML and screenshot data
                return {
                    'html': response.text,
                    'screenshot': response.headers.get('Spb-Screenshot'),
                    'success': True
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

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
            # Extract product title
            title_element = soup.find('span', {'id': 'productTitle'})
            if title_element:
                product_info['title'] = title_element.get_text().strip()

            # Look for bestseller badges (orange flags)
            bestseller_elements = soup.find_all(string=re.compile(r'#1 Best Seller|Amazon\'s Choice|Best Seller', re.I))
            if bestseller_elements:
                product_info['is_bestseller'] = True
                for elem in bestseller_elements:
                    if elem:
                        category = self.extract_category_from_bestseller(elem)
                        if category:
                            product_info['bestseller_categories'].append(category)

            # Extract ranking information - using find() which returns parent element
            rank_element = soup.find('span', string=re.compile(r'#[\d,]+ in'))
            if rank_element:
                rank_text = rank_element.get_text()
                if rank_text:
                    rank_match = re.search(r'#([\d,]+) in (.+)', rank_text)
                    if rank_match:
                        product_info['rank'] = rank_match.group(1).replace(',', '')
                        product_info['category'] = rank_match.group(2).strip()

            # Alternative ranking extraction
            if not product_info['rank']:
                rank_section = soup.find('div', {'id': 'detailBulletsWrapper_feature_div'})
                if rank_section:
                    rank_items = rank_section.find_all(string=re.compile(r'Amazon Best Sellers Rank'))
                    for item in rank_items:
                        # Implement the logic to process each rank item
                        if item and hasattr(item, 'parent'):
                            parent = item.parent
                            if parent and hasattr(parent, 'get_text'):
                                rank_text = parent.get_text()
                                if rank_text:
                                    rank_match = re.search(r'#([\d,]+) in (.+)', rank_text)
                                    if rank_match:
                                        product_info['rank'] = rank_match.group(1).replace(',', '')
                                        product_info['category'] = rank_match.group(2).strip()
                                        break

                # Try another method if still no rank found
                if not product_info['rank']:
                    # Look for rank in product details section
                    details_section = soup.find('div', {'id': 'productDetails_feature_div'})
                    if details_section:
                        # Using find_all with string= returns NavigableString objects
                        rank_elements = details_section.find_all(string=re.compile(r'#[\d,]+ in'))
                        for element in rank_elements:
                            if element:
                                # element is a NavigableString, convert to string
                                rank_text = str(element).strip()
                                if rank_text:
                                    rank_match = re.search(r'#([\d,]+) in (.+)', rank_text)
                                    if rank_match:
                                        product_info['rank'] = rank_match.group(1).replace(',', '')
                                        product_info['category'] = rank_match.group(2).strip()
                                        break

                # Final fallback - search entire page for rank pattern
                if not product_info['rank']:
                    try:
                        all_text = soup.get_text()
                        if all_text:
                            rank_matches = re.findall(r'#([\d,]+) in ([^#\n]+)', all_text)
                            if rank_matches:
                                # Take the first reasonable match
                                for rank_num, category in rank_matches:
                                    if rank_num and category and len(category.strip()) > 3:
                                        product_info['rank'] = rank_num.replace(',', '')
                                        product_info['category'] = category.strip()
                                        break
                    except Exception as e:
                        print(f"Error in final rank extraction: {e}")

        except Exception as e:
            print(f"Error extracting product info: {e}")

        return product_info

    def extract_category_from_bestseller(self, element):
        """Extract category from bestseller element"""
        try:
            # Handle both Tag and NavigableString objects
            if hasattr(element, 'find_parent'):
                # It's a Tag object
                parent = element.find_parent()
                if parent and hasattr(parent, 'get_text'):
                    text = parent.get_text()
                elif parent:
                    text = str(parent)
                else:
                    text = None
            else:
                # It's a NavigableString - get its parent
                parent = element.parent if hasattr(element, 'parent') else None
                if parent and hasattr(parent, 'get_text'):
                    text = parent.get_text()
                elif parent:
                    text = str(parent)
                else:
                    text = str(element)

            if text:
                # Look for "in [Category]" pattern
                category_match = re.search(r'in (.+?)(?:\s|$)', text)
                if category_match:
                    return category_match.group(1).strip()

        except Exception as e:
            print(f"Error extracting category: {e}")
        return None

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

        if not email or not url:
            flash('Email and URL are required!', 'error')
            return redirect(url_for('index'))

        # Validate URL
        if 'amazon.' not in url:
            flash('Please provide a valid Amazon product URL', 'error')
            return redirect(url_for('index'))

        # Initial scrape to get product info
        result = monitor.scrape_amazon_page(url)

        if not result['success']:
            flash(f'Error accessing product page: {result["error"]}', 'error')
            return redirect(url_for('index'))

        product_info = monitor.extract_product_info(result['html'])

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

        flash(f'Product "{product_info["title"]}" added successfully!', 'success')
        return redirect(url_for('dashboard', email=email))

    except Exception as e:
        flash(f'Error adding product: {str(e)}', 'error')
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
        # Decode base64 screenshot
        screenshot_data = base64.b64decode(result[0])
        return send_file(
            io.BytesIO(screenshot_data),
            mimetype='image/png',
            as_attachment=False
        )

    return "Screenshot not found", 404

@app.route('/check_products')
def manual_check():
    """Manual trigger for checking all products"""
    check_all_products()
    return jsonify({'status': 'Products checked successfully'})

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
    conn = sqlite3.connect('amazon_monitor.db')
    cursor = conn.cursor()

    cursor.execute('SELECT id, product_url FROM products WHERE active = 1')
    products = cursor.fetchall()

    for product_id, url in products:
        try:
            result = monitor.scrape_amazon_page(url)

            if result['success']:
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

                # If newly achieved bestseller status, save screenshot
                if product_info['is_bestseller']:
                    # Check if we already have a recent bestseller screenshot
                    cursor.execute('''
                        SELECT id FROM bestseller_screenshots 
                        WHERE product_id = ? AND achieved_at > ?
                    ''', (product_id, datetime.now() - timedelta(hours=1)))

                    if not cursor.fetchone() and result.get('screenshot'):
                        cursor.execute('''
                            INSERT INTO bestseller_screenshots 
                            (product_id, screenshot_data, rank_achieved, category, achieved_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            product_id, result['screenshot'], product_info['rank'],
                            product_info['category'], datetime.now()
                        ))

            # Rate limiting - wait between requests
            time.sleep(2)

        except Exception as e:
            print(f"Error checking product {product_id}: {e}")

    conn.commit()
    conn.close()

# Scheduler for automatic checking
def run_scheduler():
    schedule.every(30).minutes.do(check_all_products)  # Check every 30 minutes

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
    print("⏰ Products will be checked every 30 minutes")

    app.run(debug=True, host='0.0.0.0', port=5000)