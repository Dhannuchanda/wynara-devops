from flask import Flask, render_template, redirect, url_for, session, send_from_directory, jsonify
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from prometheus_flask_exporter import PrometheusMetrics
from extensions import limiter
import os
import sys
import logging
from dotenv import load_dotenv

# Ensure startup logs and import-time prints do not crash on Windows consoles
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Log startup
logger.info("="*60)
logger.info("🚀 Starting WAPL ID Management System")
logger.info(f"PORT environment variable: {os.environ.get('PORT', 'NOT SET')}")
logger.info("="*60)

# Load environment variables from .env file
load_dotenv()

# Import database
from database import init_db, db


# Import blueprints
from routes.auth import auth_bp
from routes.student import student_bp
from routes.admin import admin_bp
from routes.hr import hr_bp
from routes.public import public_bp
from routes.exam import exam_bp


# Initialize Flask app
app = Flask(__name__)


# Lightweight process health endpoint for container orchestration.
@app.route('/health')
def health():
    return jsonify({'status': 'ok'}), 200


# Configuration - SECRET_KEY is required in production
if not os.environ.get('SECRET_KEY'):
    if os.environ.get('FLASK_ENV') == 'production':
        raise ValueError("SECRET_KEY must be set in production!")
    # Dev fallback only
    app.config['SECRET_KEY'] = 'dev-only-key-change-in-production'
else:
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['SESSION_PERMANENT'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload

# Session Cookie Security
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # HTTPS only in prod
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# Expose application metrics for the internal monitoring network.
metrics = PrometheusMetrics(app)

# Initialize session
Session(app)

# Initialize rate limiter from extensions
limiter.init_app(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)
# API routes are exempted below - they're protected by SameSite cookies and rate limiting


# ==================== DIRECTORY SETUP ====================


def ensure_directories():
    """Create necessary directories if they don't exist"""
    base_path = '.'
    
    directories = [
        f'{base_path}/uploads/profile_pics',
        f'{base_path}/uploads/resumes',
        f'{base_path}/uploads/certificates',
        f'{base_path}/uploads/qr_codes',
        f'{base_path}/uploads/reports',
        f'{base_path}/private_uploads/hr_verifications',
        f'{base_path}/private_uploads/admin_hr_verifications',
        f'{base_path}/flask_session',
        f'{base_path}/fonts'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✓ Directory ensured: {directory}")
        except Exception as e:
            print(f"⚠ Warning: Could not create directory {directory}: {e}")
    
    return base_path



# Create directories and get base path for uploads
try:
    UPLOAD_BASE_PATH = ensure_directories()
except Exception as e:
    logger.error(f"Failed to ensure directories: {e}")
    # Fallback to current directory to prevent crash
    UPLOAD_BASE_PATH = '.'

# Initialize database
try:
    init_db()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Database initialization failed: {e}")
    logger.error("Application may not function correctly without database!")
    # In production, raise to prevent serving broken pages
    if os.environ.get('FLASK_ENV') == 'production':
        raise



# ==================== REGISTER BLUEPRINTS ====================


app.register_blueprint(auth_bp)
app.register_blueprint(student_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(hr_bp)
app.register_blueprint(public_bp)
app.register_blueprint(exam_bp)

# Exempt API blueprints from CSRF - they use JSON Content-Type + SameSite session cookies for protection
# All API routes accept only JSON (not form data), making CSRF attacks impractical
csrf.exempt(auth_bp)
csrf.exempt(student_bp)
csrf.exempt(admin_bp)
csrf.exempt(hr_bp)
csrf.exempt(public_bp)
csrf.exempt(exam_bp)


# ==================== RATE LIMITING CONFIGURATION ====================
# Default limits (200/day, 50/hour) apply to all routes
# Additional per-endpoint limits can be added using @limiter.limit() in route files

# Add rate limit error handler
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description),
        'retry_after': e.retry_after
    }), 429


# ==================== ERROR HANDLERS ====================


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


@app.errorhandler(413)
def file_too_large(error):
    return {'error': 'File size exceeds maximum limit'}, 413


# ==================== ROOT ROUTE ====================


@app.route('/')
def index():
    """Homepage route"""
    if 'user_id' in session:
        role = session.get('role')
        if role == 'student':
            # Check if student is approved (needs to take exam)
            from database import db as app_db
            student = app_db.execute_query(
                'SELECT account_status FROM students WHERE user_id = ?',
                (session['user_id'],), fetch_one=True
            )
            if student and student['account_status'] == 'approved':
                return redirect('/exam')
            return redirect(url_for('student.student_dashboard'))
        elif role == 'admin':
            return redirect(url_for('admin.admin_dashboard'))
        elif role == 'hr':
            return redirect(url_for('hr.hr_dashboard'))
    
    return render_template('index.html')


# ==================== FILE SERVING ====================


@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    """Serve uploaded files (profile pics, resumes, certificates, QR codes)"""
    uploads_dir = os.path.join(UPLOAD_BASE_PATH, 'uploads')
    
    # Determine MIME type based on file extension
    if filename.lower().endswith('.pdf'):
        mime_type = 'application/pdf'
    elif filename.lower().endswith(('.jpg', '.jpeg')):
        mime_type = 'image/jpeg'
    elif filename.lower().endswith('.png'):
        mime_type = 'image/png'
    elif filename.lower().endswith('.mp4'):
        mime_type = 'video/mp4'
    else:
        mime_type = 'application/octet-stream'
    
    return send_from_directory(uploads_dir, filename, mimetype=mime_type)


@app.route('/download/<path:filename>')
def download_file(filename):
    """Download uploaded files as attachments (forces download instead of view)"""
    uploads_dir = os.path.join(UPLOAD_BASE_PATH, 'uploads')
    
    # Determine MIME type based on file extension
    if filename.lower().endswith('.pdf'):
        mime_type = 'application/pdf'
    elif filename.lower().endswith(('.jpg', '.jpeg')):
        mime_type = 'image/jpeg'
    elif filename.lower().endswith('.png'):
        mime_type = 'image/png'
    else:
        mime_type = 'application/octet-stream'
    
    # Use as_attachment=True to force download
    return send_from_directory(
        uploads_dir, 
        filename, 
        mimetype=mime_type,
        as_attachment=True,
        download_name=filename.split('_', 2)[-1] if '_' in filename else filename
    )


# ==================== CONTEXT PROCESSOR ====================

# ==================== CONTEXT PROCESSOR ====================


@app.context_processor
def inject_user():
    """Make user info available in all templates"""
    return {
        'logged_in': 'user_id' in session,
        'user_role': session.get('role'),
        'user_id': session.get('user_id')
    }


# ==================== APPLICATION STARTUP ====================


if __name__ == '__main__':
    # Display startup message
    print("\n" + "="*60)
    print("🚀 Starting WAPL ID Management System")
    print("="*60)
    print("✅ Database initialized successfully")
    
    # Get port from environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    
    print(f"\n📍 Server starting on http://0.0.0.0:{port}")
    print(f"🔧 Debug mode: {debug_mode}")
    print("="*60 + "\n")
    
    # Run the Flask development server
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug_mode
    )
