from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import string
import random
import re
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse
from user_agents import parse

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

# Security middleware
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

class ShortUrl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_code = db.Column(db.String(20), unique=True, nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_custom = db.Column(db.Boolean, default=False)
    
    # Relationship to analytics
    analytics = db.relationship('UrlAnalytics', backref='url', lazy=True, cascade='all, delete-orphan')

class UrlAnalytics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('short_url.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    referrer = db.Column(db.String(500))
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    device_type = db.Column(db.String(50))
    browser = db.Column(db.String(100))
    platform = db.Column(db.String(100))
    is_bot = db.Column(db.Boolean, default=False)

# Create tables
with app.app_context():
    db.create_all()

# Security Helper Functions
def sanitize_input(text):
    """Enhanced sanitization for SQL injection and XSS prevention"""
    if not text:
        return ""
    
    # Remove SQL injection patterns
    sql_patterns = [
        "'", "\"", ";", "--", "/*", "*/", "xp_", "exec ", 
        "union", "select", "insert", "update", "delete",
        "drop", "create", "alter", "truncate", "schema",
        "table", "database", "procedure", "function"
    ]
    
    for pattern in sql_patterns:
        text = re.sub(re.escape(pattern), '', text, flags=re.IGNORECASE)
    
    # Remove HTML tags and dangerous protocols
    text = re.sub(r'<[^>]*>', '', text)
    text = re.sub(r'[\x00-\x1F\x7F]', '', text)
    
    dangerous_patterns = [
        'javascript:', 'data:', 'vbscript:', 'file://', 
        'ftp://', 'tel:', 'mailto:', 'about:', 'blob:',
        '\\x00', '\\x05', '\\x92', '<!--', '-->'
    ]
    
    for pattern in dangerous_patterns:
        text = text.replace(pattern, '')
    
    return text.strip()

def is_valid_url(url):
    """Validate URL safety - only allow http/https"""
    try:
        if not url:
            return False
            
        test_url = url.lower()
        if not test_url.startswith(('http://', 'https://')):
            test_url = 'http://' + test_url
            
        parsed = urlparse(test_url)
        
        if parsed.scheme not in ['http', 'https']:
            return False
            
        dangerous_patterns = [
            'javascript:', 'data:', 'vbscript:', 'file://', 
            'ftp://', 'tel:', 'mailto:', '<', '>', '"', "'",
            '\\x00', '\\x05', '\\x92', '../', './', '..\\'
        ]
        
        if any(pattern in test_url for pattern in dangerous_patterns):
            return False
            
        if not parsed.netloc or '.' not in parsed.netloc:
            return False
            
        return True
        
    except:
        return False

def is_valid_short_code(code):
    """Strict short code validation"""
    if not code:
        return False
        
    # Only allow alphanumeric, hyphens, underscores (3-20 chars)
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', code):
        return False
    
    # Block any attempt at path traversal or injection
    malicious_patterns = [
        '..', '/', '\\', ':', ';', "'", '"', '<', '>', 
        'javascript', 'data', 'file', 'ftp', 'tel', 'mailto',
        'about', 'blob', '%00', '%05', '%92'
    ]
    
    code_lower = code.lower()
    if any(pattern in code_lower for pattern in malicious_patterns):
        return False
        
    reserved_words = [
        'admin', 'login', 'signup', 'dashboard', 'api', 
        'static', 'user', 'logout', 'delete', 'shorten',
        'redirect', 'url', 'create', 'edit', 'update'
    ]
    
    if code_lower in reserved_words:
        return False
        
    return True

def generate_short_code(length=8):
    """Generate secure random short code"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

def get_user_url_count(user_id):
    """Safe database query"""
    return db.session.query(ShortUrl).filter_by(user_id=user_id).count()

def is_account_locked(user):
    """Check if user account is temporarily locked"""
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
    return False

def prepare_analytics_data(analytics_data):
    """Prepare analytics data for charts"""
    # Click timeline (last 30 days)
    today = datetime.utcnow()
    timeline = {}
    for i in range(30):
        date = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        timeline[date] = 0
    
    # Count data
    countries = {}
    devices = {}
    browsers = {}
    platforms = {}
    referrers = {}
    
    for entry in analytics_data:
        # Timeline
        date = entry.timestamp.strftime('%Y-%m-%d')
        if date in timeline:
            timeline[date] += 1
        
        # Countries
        countries[entry.country] = countries.get(entry.country, 0) + 1
        
        # Devices
        devices[entry.device_type] = devices.get(entry.device_type, 0) + 1
        
        # Browsers
        browsers[entry.browser] = browsers.get(entry.browser, 0) + 1
        
        # Platforms
        platforms[entry.platform] = platforms.get(entry.platform, 0) + 1
        
        # Referrers
        if entry.referrer and entry.referrer not in ['', 'direct']:
            domain = urlparse(entry.referrer).netloc
            referrers[domain] = referrers.get(domain, 0) + 1
    
    return {
        'timeline': timeline,
        'countries': countries,
        'devices': devices,
        'browsers': browsers,
        'platforms': platforms,
        'referrers': dict(sorted(referrers.items(), key=lambda x: x[1], reverse=True)[:10]),
        'total_clicks': len(analytics_data)
    }

# Security Middleware
@app.before_request
def security_checks():
    """Comprehensive security checks for all requests"""
    
    # Block non-standard HTTP methods
    if request.method not in ['GET', 'POST', 'HEAD', 'OPTIONS']:
        return jsonify({"error": "Method not allowed"}), 405
        
    # Block requests with control characters or binary data
    path = request.path + request.query_string.decode()
    if any(ord(char) < 32 or ord(char) > 126 for char in path):
        return jsonify({"error": "Bad request"}), 400
        
    # Block common attack patterns
    attack_patterns = [
        '../', './', '/etc/', '/passwd', '/win.ini', 'cmd.exe',
        'select ', 'union ', 'insert ', 'update ', 'delete ',
        'drop ', 'create ', 'exec ', 'xp_', '--', '/*', '*/'
    ]
    
    request_data = request.path + request.query_string.decode()
    if any(pattern in request_data.lower() for pattern in attack_patterns):
        return jsonify({"error": "Bad request"}), 400

@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers"""
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline';",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
        
    return response

# Flask-Login configuration
@login_manager.user_loader
def load_user(user_id):
    """Safe user loading"""
    try:
        return db.session.get(User, int(user_id))
    except:
        return None

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return render_template('login.html')
        
        # SECURE: Parameterized query
        user = db.session.query(User).filter(User.email == email).first()
        
        if user:
            if is_account_locked(user):
                flash('Account temporarily locked. Please try again later.', 'error')
                return render_template('login.html')
            
            if check_password_hash(user.password, password):
                # Successful login
                user.login_attempts = 0
                user.locked_until = None
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                # Failed login attempt
                user.login_attempts += 1
                if user.login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    flash('Account locked due to multiple failed attempts. Try again in 30 minutes.', 'error')
                else:
                    flash('Invalid email or password', 'error')
                db.session.commit()
        else:
            flash('Invalid email or password', 'error')
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        
        # Validation
        if not all([username, email, password]):
            flash('Please fill all fields', 'error')
            return redirect(url_for('signup'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('signup'))
        
        # SECURE: Parameterized queries
        existing_email = db.session.query(User).filter(User.email == email).first()
        existing_username = db.session.query(User).filter(User.username == username).first()
        
        if existing_email:
            flash('Email already exists', 'error')
            return redirect(url_for('signup'))
        
        if existing_username:
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
        
        # Create user with secure password hashing
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        
        return redirect(url_for('dashboard'))
        
    return render_template('signup.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        original_url = sanitize_input(request.form.get('original_url', '').strip())
        custom_code = sanitize_input(request.form.get('custom_code', '').strip())
        
        # Validate URL
        if not original_url:
            flash('Please enter a URL', 'error')
            return redirect(url_for('dashboard'))
        
        if not is_valid_url(original_url):
            flash('Invalid URL format. Only http/https URLs are allowed.', 'error')
            return redirect(url_for('dashboard'))
        
        # Check free plan limit
        url_count = db.session.query(ShortUrl).filter_by(user_id=current_user.id).count()
        if not current_user.is_premium and url_count >= 200:
            flash('Free plan limit reached (200 URLs). Upgrade to premium for unlimited URLs.', 'error')
            return redirect(url_for('dashboard'))
        
        # Handle custom code for premium users
        if custom_code and current_user.is_premium:
            if not is_valid_short_code(custom_code):
                flash('Invalid custom code. Use only letters, numbers, hyphens, and underscores (3-20 characters).', 'error')
                return redirect(url_for('dashboard'))
            
            # SECURE: Parameterized query
            existing_code = db.session.query(ShortUrl).filter(ShortUrl.short_code == custom_code).first()
            if existing_code:
              
                return redirect(url_for('dashboard'))
            
            short_code = custom_code
            is_custom = True
        else:
            short_code = generate_short_code()
            is_custom = False
        
        # Create URL entry
        new_url = ShortUrl(
            original_url=original_url,
            short_code=short_code,
            user_id=current_user.id,
            is_custom=is_custom
        )
        
        db.session.add(new_url)
        db.session.commit()
        
        
        return redirect(url_for('dashboard'))
    
    # GET request - show user's URLs
    user_urls = db.session.query(ShortUrl).filter_by(user_id=current_user.id).order_by(ShortUrl.created_at.desc()).all()
    return render_template('dashboard.html', urls=user_urls, user=current_user)

@app.route('/upgrade')
@login_required
def upgrade():
    """Premium upgrade page"""
    return render_template('upgrade.html', user=current_user)

@app.route('/analytics/<int:url_id>')
@login_required
def analytics(url_id):
    """Detailed analytics for a specific URL - AVAILABLE FOR FREE USERS"""
    url = db.session.query(ShortUrl).filter_by(id=url_id, user_id=current_user.id).first()
    
    if not url:
        flash('', 'error')
        return redirect(url_for('dashboard'))
    
    # Get analytics data
    analytics_data = db.session.query(UrlAnalytics).filter_by(url_id=url_id).order_by(UrlAnalytics.timestamp.desc()).all()
    
    # Prepare data for charts
    chart_data = prepare_analytics_data(analytics_data)
    
    return render_template('analytics.html', url=url, analytics=analytics_data, chart_data=chart_data, user=current_user)

@app.route('/<short_code>')
def redirect_to_url(short_code):
    # Validate short code to prevent abuse
    if not is_valid_short_code(short_code):
        return "Invalid URL", 404
    
    # SECURE: Parameterized query
    url = db.session.query(ShortUrl).filter(ShortUrl.short_code == short_code).first()
    if not url:
        return "URL not found", 404
    
    # Record analytics
    try:
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        ip = request.remote_addr
        
        # Parse user agent for detailed analytics
        ua = parse(user_agent)
        device_type = 'mobile' if ua.is_mobile else 'tablet' if ua.is_tablet else 'desktop'
        browser = ua.browser.family
        platform = ua.os.family
        
        analytics_entry = UrlAnalytics(
            url_id=url.id,
            ip_address=ip,
            user_agent=user_agent,
            referrer=referrer,
            country='Unknown',
            city='Unknown',
            device_type=device_type,
            browser=browser,
            platform=platform,
            is_bot=ua.is_bot
        )
        
        db.session.add(analytics_entry)
        url.clicks += 1
        db.session.commit()
        
    except Exception as e:
        print(f"Analytics error: {e}")
        db.session.rollback()
        url.clicks += 1
        db.session.commit()
    
    return redirect(url.original_url)

@app.route('/delete/<int:url_id>')
@login_required
def delete_url(url_id):
    # SECURE: Parameterized query with authorization check
    url = db.session.query(ShortUrl).filter_by(id=url_id, user_id=current_user.id).first()
    
    if not url:
        flash('', 'error')
        return redirect(url_for('dashboard'))
    
    db.session.delete(url)
    db.session.commit()
    
    flash('', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('', 'success')
    return redirect(url_for('login'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)