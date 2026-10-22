import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from contextlib import contextmanager
import secrets
import string
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
DB_NAME = 'wynara.db'
# Always resolve SQLite DB relative to this file, not the current working directory.
# Otherwise starting the app from a different folder silently creates/uses a different DB.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)

# Import psycopg2 if available for PostgreSQL
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    logger.info("psycopg2 not available, using SQLite only")

def get_db_type():
    """Return database type"""
    if DATABASE_URL and POSTGRES_AVAILABLE:
        return 'postgres'
    return 'sqlite'

def get_agg_func():
    """Return the correct string aggregation function"""
    if get_db_type() == 'postgres':
        return "STRING_AGG(d.domain_name, ', ')"
    return "GROUP_CONCAT(d.domain_name, ', ')"

def is_postgres():
    """Check if using PostgreSQL"""
    return get_db_type() == 'postgres'

def get_bool_value(value):
    """Return proper boolean representation for the current database"""
    if is_postgres():
        return 'TRUE' if value else 'FALSE'
    return 1 if value else 0

def get_bool_literal(value):
    """Return SQL literal for boolean in queries (for f-strings)"""
    if is_postgres():
        return 'TRUE' if value else 'FALSE'
    return '1' if value else '0'

def get_db_error():
    """Return the appropriate IntegrityError class for current database"""
    if is_postgres() and POSTGRES_AVAILABLE:
        import psycopg2
        return psycopg2.IntegrityError
    return sqlite3.IntegrityError

@contextmanager
def get_db_connection():
    """Get database connection (PostgreSQL or SQLite)"""
    conn = None
    
    try:
        if is_postgres():
            # PostgreSQL Connection
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
            yield conn
        else:
            # SQLite Connection with 30-second timeout to prevent lock errors
            conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrency
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA busy_timeout=30000')  # 30 seconds
            yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def init_db():
    """Initialize database with all tables"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Database-specific types
            if is_postgres():
                pk_type = "SERIAL PRIMARY KEY"
                datetime_default = "DEFAULT CURRENT_TIMESTAMP"
                bool_true = "TRUE"
                placeholder = "%s"
            else:
                pk_type = "INTEGER PRIMARY KEY AUTOINCREMENT"
                datetime_default = "DEFAULT CURRENT_TIMESTAMP"
                bool_true = "1"
                placeholder = "?"

            # Users table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS users (
                    id {pk_type},
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('student', 'hr', 'admin')),
                    is_verified BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP {datetime_default},
                    last_login TIMESTAMP
                )
            ''')
            
            # Domains table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS domains (
                    id {pk_type},
                    domain_name TEXT NOT NULL UNIQUE,
                    is_active BOOLEAN DEFAULT TRUE,
                    price INTEGER DEFAULT 166,
                    created_at TIMESTAMP {datetime_default},
                    created_by_admin_id INTEGER
                )
            ''')
            
            # Add price column if it doesn't exist (migration for existing databases)
            try:
                if is_postgres():
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS price INTEGER DEFAULT 166")
                else:
                    cursor.execute("ALTER TABLE domains ADD COLUMN price INTEGER DEFAULT 166")
                conn.commit()
            except Exception:
                pass  # Column already exists
            
            # Admins table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS admins (
                    id {pk_type},
                    user_id INTEGER NOT NULL,
                    full_name TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    is_super_admin INTEGER DEFAULT 0,
                    is_owner INTEGER DEFAULT 0,
                    created_by_admin_id INTEGER,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (created_by_admin_id) REFERENCES admins(id)
                )
            ''')

            try:
                if is_postgres():
                    cursor.execute("ALTER TABLE admins ADD COLUMN IF NOT EXISTS is_owner INTEGER DEFAULT 0")
                else:
                    cursor.execute("ALTER TABLE admins ADD COLUMN is_owner INTEGER DEFAULT 0")
                conn.commit()
            except Exception:
                pass
            
            # HRs table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS hrs (
                    id {pk_type},
                    user_id INTEGER NOT NULL,
                    full_name TEXT NOT NULL,
                    company_name TEXT NOT NULL,
                    years_of_experience INTEGER DEFAULT 0,
                    phone TEXT NOT NULL,
                    designation TEXT NOT NULL,
                    verification_proof_path TEXT,
                    admin_verification_proof_path TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    rejection_reason TEXT,
                    approved_at TIMESTAMP,
                    rejected_at TIMESTAMP,
                    reviewed_by_admin_id INTEGER,
                    reviewed_at TIMESTAMP,
                    created_by_admin_id INTEGER,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (created_by_admin_id) REFERENCES admins(id),
                    FOREIGN KEY (reviewed_by_admin_id) REFERENCES admins(id)
                )
            ''')

            # Migrations for older SQLite databases that have a minimal hrs table.
            # SQLite doesn't support ADD COLUMN IF NOT EXISTS, so we attempt and ignore failures.
            try:
                if is_postgres():
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS company_name TEXT NOT NULL DEFAULT ''")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS years_of_experience INTEGER DEFAULT 0")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS designation TEXT NOT NULL DEFAULT ''")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS verification_proof_path TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS admin_verification_proof_path TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS rejection_reason TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMP")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS reviewed_by_admin_id INTEGER")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP")
                else:
                    for coldef in (
                        "company_name TEXT",
                        "years_of_experience INTEGER DEFAULT 0",
                        "designation TEXT",
                        "verification_proof_path TEXT",
                        "admin_verification_proof_path TEXT",
                        "status TEXT DEFAULT 'pending'",
                        "rejection_reason TEXT",
                        "approved_at TIMESTAMP",
                        "rejected_at TIMESTAMP",
                        "reviewed_by_admin_id INTEGER",
                        "reviewed_at TIMESTAMP",
                    ):
                        try:
                            cursor.execute(f"ALTER TABLE hrs ADD COLUMN {coldef}")
                        except Exception:
                            pass

                # Backfill status for legacy rows
                try:
                    cursor.execute("UPDATE hrs SET status = 'pending' WHERE status IS NULL OR TRIM(status) = ''")
                except Exception:
                    pass
                conn.commit()
            except Exception:
                pass
            
            # Students table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS students (
                    id {pk_type},
                    user_id INTEGER NOT NULL,
                    wapl_id TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    profile_pic TEXT,
                    resume TEXT,
                    domain_id INTEGER,
                    registration_date TIMESTAMP {datetime_default},
                    certificate_issued_date TIMESTAMP,
                    certificate_expiry_date TIMESTAMP,
                    assigned_hr_id INTEGER,
                    address TEXT,
                    education_details TEXT,
                    skills TEXT,
                    projects TEXT,
                    account_status TEXT NOT NULL DEFAULT 'pending',
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (domain_id) REFERENCES domains(id),
                    FOREIGN KEY (assigned_hr_id) REFERENCES hrs(id)
                )
            ''')

            # Student-Domain junction table (MANY-TO-MANY)
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS student_domains (
                    id {pk_type},
                    student_id INTEGER NOT NULL,
                    domain_id INTEGER NOT NULL,
                    created_at TIMESTAMP {datetime_default},
                    expires_at TIMESTAMP,
                    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
                    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                    UNIQUE(student_id, domain_id)
                )
            ''')

            try:
                if is_postgres():
                    cursor.execute("ALTER TABLE student_domains ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP")
                else:
                    cursor.execute("ALTER TABLE student_domains ADD COLUMN expires_at TIMESTAMP")
                conn.commit()
            except Exception:
                pass

            try:
                cursor.execute('SELECT id, created_at FROM student_domains WHERE expires_at IS NULL')
                rows_without_expiry = cursor.fetchall()
                for row in rows_without_expiry:
                    row_id = row['id'] if is_postgres() else row[0]
                    created_at = row['created_at'] if is_postgres() else row[1]
                    cursor.execute(
                        'UPDATE student_domains SET expires_at = ? WHERE id = ?',
                        (get_subscription_expiry(created_at), row_id)
                    )
                if rows_without_expiry:
                    conn.commit()
            except Exception:
                pass
            
            # OTP verifications table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS otp_verifications (
                    id {pk_type},
                    user_id INTEGER NOT NULL,
                    otp_code TEXT NOT NULL,
                    purpose TEXT NOT NULL CHECK(purpose IN ('registration', 'login', 'password_reset')),
                    is_used BOOLEAN DEFAULT FALSE,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')

            # HR <-> Student in-app messages
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS hr_student_messages (
                    id {pk_type},
                    student_id INTEGER NOT NULL,
                    hr_id INTEGER NOT NULL,
                    sender_role TEXT NOT NULL CHECK(sender_role IN ('student', 'hr')),
                    message_text TEXT NOT NULL,
                    is_read BOOLEAN DEFAULT FALSE,
                    read_at TIMESTAMP,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
                    FOREIGN KEY (hr_id) REFERENCES hrs(id) ON DELETE CASCADE
                )
            ''')

            # Migrate older DBs that don't have the table (handled by CREATE TABLE).
            try:
                conn.commit()
            except Exception:
                pass
            
            # Certificates table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS certificates (
                    id {pk_type},
                    student_id INTEGER NOT NULL,
                    certificate_unique_id TEXT UNIQUE NOT NULL,
                    issue_date TIMESTAMP NOT NULL,
                    expiry_date TIMESTAMP NOT NULL,
                    qr_code TEXT NOT NULL,
                    pdf_path TEXT NOT NULL,
                    report_file TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    issued_by_hr_id INTEGER,
                    display_name TEXT,
                    FOREIGN KEY (student_id) REFERENCES students(id),
                    FOREIGN KEY (issued_by_hr_id) REFERENCES hrs(id)
                )
            ''')
            
            # Add report_file column if it doesn't exist (migration for existing databases)
            try:
                if is_postgres():
                    cursor.execute("ALTER TABLE certificates ADD COLUMN IF NOT EXISTS report_file TEXT")
                else:
                    cursor.execute("ALTER TABLE certificates ADD COLUMN report_file TEXT")
                conn.commit()
            except Exception:
                pass  # Column already exists

            # Add company_website and address columns to hrs table if they don't exist
            try:
                if is_postgres():
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS company_website TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS address TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS years_of_experience INTEGER DEFAULT 0")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS verification_proof_path TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS admin_verification_proof_path TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS rejection_reason TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMP")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS reviewed_by_admin_id INTEGER")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP")
                else:
                    cursor.execute("ALTER TABLE hrs ADD COLUMN company_website TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN address TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN years_of_experience INTEGER DEFAULT 0")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN verification_proof_path TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN admin_verification_proof_path TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN rejection_reason TEXT")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN approved_at TIMESTAMP")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN rejected_at TIMESTAMP")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN reviewed_by_admin_id INTEGER")
                    cursor.execute("ALTER TABLE hrs ADD COLUMN reviewed_at TIMESTAMP")
                conn.commit()
            except Exception:
                pass  # Columns already exist

            # Backfill existing HRs so previously created accounts remain usable
            try:
                cursor.execute("""
                    UPDATE hrs
                    SET status = 'approved',
                        approved_at = COALESCE(approved_at, created_at)
                """)
                conn.commit()
            except Exception:
                pass

            # Student Projects table (for project portfolio gallery)
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS student_projects (
                    id {pk_type},
                    student_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    image_path TEXT,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
                )
            ''')

            # Add short_code column to domains table if it doesn't exist
            try:
                if is_postgres():
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS short_code TEXT")
                else:
                    cursor.execute("ALTER TABLE domains ADD COLUMN short_code TEXT")
                conn.commit()
            except Exception:
                pass  # Column already exists

            # Auto-populate short_code for existing domains that don't have one
            try:
                domains_without_code = []
                if is_postgres():
                    cursor.execute("SELECT id, domain_name FROM domains WHERE short_code IS NULL OR short_code = ''")
                else:
                    cursor.execute("SELECT id, domain_name FROM domains WHERE short_code IS NULL OR short_code = ''")
                domains_without_code = cursor.fetchall()

                for domain_row in domains_without_code:
                    d_id = domain_row['id'] if is_postgres() else domain_row[0]
                    d_name = domain_row['domain_name'] if is_postgres() else domain_row[1]
                    code = generate_short_code(d_name)
                    if is_postgres():
                        cursor.execute("UPDATE domains SET short_code = %s WHERE id = %s", (code, d_id))
                    else:
                        cursor.execute("UPDATE domains SET short_code = ? WHERE id = ?", (code, d_id))
                if domains_without_code:
                    conn.commit()
                    print(f"✅ Auto-generated short codes for {len(domains_without_code)} domains")
            except Exception as e:
                logger.warning(f"Could not auto-populate short codes: {e}")

            # Add cooldown_until column to students table (exam system migration)
            try:
                if is_postgres():
                    cursor.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS cooldown_until TIMESTAMP")
                else:
                    cursor.execute("ALTER TABLE students ADD COLUMN cooldown_until TIMESTAMP")
                conn.commit()
            except Exception:
                pass  # Column already exists

            # HR profile change requests table (admin approval workflow)
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS hr_profile_changes (
                    id {pk_type},
                    hr_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    changes TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    reviewed_by_admin_id INTEGER,
                    review_notes TEXT,
                    created_at TIMESTAMP {datetime_default},
                    reviewed_at TIMESTAMP,
                    FOREIGN KEY (hr_id) REFERENCES hrs(id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (reviewed_by_admin_id) REFERENCES admins(id)
                )
            ''')

            # Recruitment status table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS recruitment_status (
                    id {pk_type},
                    student_id INTEGER NOT NULL,
                    hr_id INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'viewed',
                    notes TEXT,
                    created_at TIMESTAMP {datetime_default},
                    updated_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (student_id) REFERENCES students(id),
                    FOREIGN KEY (hr_id) REFERENCES hrs(id)
                )
            ''')

            # Certificate audit table
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS certificate_audit (
                    id {pk_type},
                    certificate_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT,
                    changed_by_admin_id INTEGER,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (certificate_id) REFERENCES certificates(id),
                    FOREIGN KEY (changed_by_admin_id) REFERENCES users(id)
                )
            ''')

            # Payments table for Razorpay integration
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS payments (
                    id {pk_type},
                    razorpay_order_id TEXT UNIQUE NOT NULL,
                    razorpay_payment_id TEXT,
                    razorpay_signature TEXT,
                    email TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    currency TEXT DEFAULT 'INR',
                    domain_count INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMP {datetime_default},
                    verified_at TIMESTAMP
                )
            ''')

            # Settings table for admin-configurable options
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS settings (
                    id {pk_type},
                    setting_key TEXT UNIQUE NOT NULL,
                    setting_value TEXT NOT NULL,
                    description TEXT,
                    updated_at TIMESTAMP {datetime_default},
                    updated_by_admin_id INTEGER
                )
            ''')

            # ==================== EXAM SYSTEM TABLES (OFFLINE) ====================

            # Exam configuration per domain
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS exam_config (
                    id {pk_type},
                    domain_id INTEGER NOT NULL UNIQUE,
                    max_marks INTEGER DEFAULT 100,
                    passing_marks INTEGER DEFAULT 40,
                    cooldown_days INTEGER DEFAULT 90,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP {datetime_default},
                    updated_by_admin_id INTEGER,
                    FOREIGN KEY (domain_id) REFERENCES domains(id)
                )
            ''')

            # Exam schedule windows (domain-wise, offline with venue)
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS exam_schedules (
                    id {pk_type},
                    domain_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    exam_date DATE NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    venue TEXT NOT NULL,
                    venue_address TEXT,
                    max_students INTEGER DEFAULT 50,
                    instructions TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_by_admin_id INTEGER,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (domain_id) REFERENCES domains(id),
                    FOREIGN KEY (created_by_admin_id) REFERENCES admins(id)
                )
            ''')

            # Student exam registrations (student registers for a schedule slot)
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS exam_registrations (
                    id {pk_type},
                    student_id INTEGER NOT NULL,
                    schedule_id INTEGER NOT NULL,
                    seat_number TEXT,
                    status TEXT DEFAULT 'registered',
                    registered_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (student_id) REFERENCES students(id),
                    FOREIGN KEY (schedule_id) REFERENCES exam_schedules(id),
                    UNIQUE(student_id, schedule_id)
                )
            ''')

            # Exam results (admin manually enters marks)
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS exam_results (
                    id {pk_type},
                    student_id INTEGER NOT NULL,
                    schedule_id INTEGER NOT NULL,
                    domain_id INTEGER NOT NULL,
                    marks_obtained INTEGER NOT NULL,
                    max_marks INTEGER NOT NULL,
                    passing_marks INTEGER NOT NULL,
                    passed BOOLEAN DEFAULT FALSE,
                    remarks TEXT,
                    entered_by_admin_id INTEGER,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (student_id) REFERENCES students(id),
                    FOREIGN KEY (schedule_id) REFERENCES exam_schedules(id),
                    FOREIGN KEY (domain_id) REFERENCES domains(id),
                    FOREIGN KEY (entered_by_admin_id) REFERENCES admins(id)
                )
            ''')

            # ==================== DOMAIN COOLDOWNS TABLE ====================
            # Track per-domain cooldowns when a student fails a specific domain exam
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS domain_cooldowns (
                    id {pk_type},
                    student_id INTEGER NOT NULL,
                    domain_id INTEGER NOT NULL,
                    cooldown_until TIMESTAMP NOT NULL,
                    failed_at TIMESTAMP {datetime_default},
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
                    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                    UNIQUE(student_id, domain_id)
                )
            ''')

            # ==================== ACTIVITY LOG TABLE ====================
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id {pk_type},
                    user_id INTEGER,
                    user_role TEXT NOT NULL,
                    user_name TEXT,
                    user_email TEXT,
                    action TEXT NOT NULL,
                    category TEXT NOT NULL,
                    target_type TEXT,
                    target_id INTEGER,
                    target_name TEXT,
                    details TEXT,
                    ip_address TEXT,
                    created_at TIMESTAMP {datetime_default},
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')

            conn.commit()
            
            # Initialize default data if empty
            cursor.execute("SELECT COUNT(*) as count FROM users")
            result = cursor.fetchone()
            count = result['count'] if is_postgres() else result[0]

            if count == 0:
                print("🆕 Empty database detected, initializing defaults...")
                # Pre-populate domains
                default_domains = ['AI', 'ML', 'DevOps', 'Web Development', 'Data Science']
                for domain in default_domains:
                    if is_postgres():
                        cursor.execute(f"INSERT INTO domains (domain_name, is_active) VALUES (%s, TRUE) ON CONFLICT (domain_name) DO NOTHING", (domain,))
                    else:
                        cursor.execute('INSERT OR IGNORE INTO domains (domain_name, is_active) VALUES (?, 1)', (domain,))
                
                # Create default SUPER admin account
                admin_email = 'admin@wapl.com'
                admin_password_hash = generate_password_hash('admin123')
                
                if is_postgres():
                    cursor.execute("INSERT INTO users (email, password_hash, role, is_verified) VALUES (%s, %s, 'admin', TRUE) RETURNING id", 
                                  (admin_email, admin_password_hash))
                    admin_user_id = cursor.fetchone()['id']
                    cursor.execute("INSERT INTO admins (user_id, full_name, phone, is_super_admin) VALUES (%s, 'Super Admin', '1234567890', 1)", 
                                  (admin_user_id,))
                else:
                    cursor.execute("INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, 'admin', ?)", 
                                  (admin_email, admin_password_hash, 1))
                    admin_user_id = cursor.lastrowid
                    cursor.execute("INSERT INTO admins (user_id, full_name, phone, is_super_admin) VALUES (?, 'Super Admin', '1234567890', 1)", 
                                  (admin_user_id,))
                print("✅ Default Super Admin created")
                conn.commit()

            # Initialize default settings if empty
            cursor.execute("SELECT COUNT(*) as count FROM settings")
            result = cursor.fetchone()
            settings_count = result['count'] if is_postgres() else result[0]
            
            if settings_count == 0:
                default_settings = [
                    ('domain_price_inr', '166', 'Price per domain in INR (₹2 ≈ $2)'),
                    ('payment_enabled', 'true', 'Enable/disable payment gateway'),
                    ('currency', 'INR', 'Payment currency'),
                ]
                for key, value, desc in default_settings:
                    if is_postgres():
                        cursor.execute("INSERT INTO settings (setting_key, setting_value, description) VALUES (%s, %s, %s) ON CONFLICT (setting_key) DO NOTHING",
                                      (key, value, desc))
                    else:
                        cursor.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value, description) VALUES (?, ?, ?)",
                                      (key, value, desc))
                print("✅ Default settings initialized")
                conn.commit()

            # Ensure key super-admin accounts keep elevated privileges across restarts
            protected_super_admin_emails = {
                'admin@wapl.com',
                'chandadhanush60@gmail.com',
            }
            for super_admin_email in protected_super_admin_emails:
                cursor.execute("SELECT id FROM users WHERE email = ? AND role = 'admin'", (super_admin_email,))
                user_row = cursor.fetchone()
                if not user_row:
                    continue

                user_id = user_row['id'] if is_postgres() else user_row[0]
                cursor.execute("SELECT id FROM admins WHERE user_id = ?", (user_id,))
                admin_row = cursor.fetchone()
                if admin_row:
                    admin_id = admin_row['id'] if is_postgres() else admin_row[0]
                    cursor.execute("UPDATE admins SET is_super_admin = 1 WHERE id = ?", (admin_id,))
                else:
                    cursor.execute(
                        "INSERT INTO admins (user_id, full_name, phone, is_super_admin) VALUES (?, ?, ?, 1)",
                        (user_id, 'Super Admin', '1234567890')
                    )
                conn.commit()

            db_type = "PostgreSQL" if is_postgres() else "SQLite"
            print(f"✅ Database initialized successfully ({db_type})")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        logger.warning("⚠️ App will start but database features may not work until DB is accessible")

def convert_query(query):
    """Convert SQLite query syntax to PostgreSQL if needed"""
    if is_postgres():
        # Replace ? placeholders with %s
        converted = query.replace('?', '%s')
        # Replace INSERT OR IGNORE with INSERT ... ON CONFLICT DO NOTHING
        if 'INSERT OR IGNORE' in converted.upper():
            converted = converted.replace('INSERT OR IGNORE', 'INSERT')
            # Add ON CONFLICT DO NOTHING if not already present
            if 'ON CONFLICT' not in converted.upper():
                # Find the end of VALUES clause
                converted = converted.rstrip().rstrip(';') + ' ON CONFLICT DO NOTHING'
        
        # Add RETURNING id to INSERT statements if not already present
        if converted.strip().upper().startswith('INSERT') and 'RETURNING' not in converted.upper():
            converted = converted.rstrip().rstrip(';') + ' RETURNING id'
        
        return converted
    return query


# Database helper class
class db:
    @staticmethod
    def execute_query(query, params=(), fetch_one=False, fetch_all=False):
        """Execute query with proper connection handling"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Convert query for database compatibility
            converted_query = convert_query(query)
            
            try:
                cursor.execute(converted_query, params)
            except Exception as e:
                print(f"❌ Query Error: {e} | Query: {converted_query}")
                raise e
            
            # Determine if this is a write operation
            is_write = query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP'))
            
            if fetch_one:
                result = cursor.fetchone()
                if is_write:
                    conn.commit()
                
                if result is None:
                    return None
                # PostgreSQL RealDictCursor returns dict, SQLite Row needs conversion
                return dict(result) if not isinstance(result, dict) else result
                
            elif fetch_all:
                results = cursor.fetchall()
                if is_write:
                    conn.commit()
                # PostgreSQL RealDictCursor returns dicts, SQLite Row needs conversion
                return [dict(row) if not isinstance(row, dict) else row for row in results]
                
            else:
                # For INSERT/UPDATE/DELETE operations
                last_id = None
                
                if query.strip().upper().startswith('INSERT'):
                    if is_postgres():
                        # For PostgreSQL, fetch the RETURNING id result
                        result = cursor.fetchone()
                        last_id = result['id'] if result else None
                    else:
                        last_id = cursor.lastrowid
                        
                conn.commit()
                return last_id
    
    @staticmethod
    def execute_many(query, params_list):
        """Execute multiple queries (batch insert/update).
        
        Note: Strips RETURNING clause added by convert_query() since
        executemany results are not consumed.
        """
        converted = convert_query(query)
        # Strip RETURNING clause — executemany doesn't aggregate results
        if is_postgres() and ' RETURNING ' in converted.upper():
            import re
            converted = re.sub(r'\s+RETURNING\s+\w+', '', converted, flags=re.IGNORECASE)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(converted, params_list)
            conn.commit()


# Settings helper functions
def get_setting(key, default=None):
    """Get a setting value from database"""
    try:
        result = db.execute_query(
            "SELECT setting_value FROM settings WHERE setting_key = ?",
            (key,), fetch_one=True
        )
        if result:
            return result['setting_value']
        return default
    except Exception as e:
        logger.error(f"Error getting setting {key}: {e}")
        return default


def set_setting(key, value, description=None, admin_id=None):
    """Set a setting value in database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            if is_postgres():
                cursor.execute("""
                    INSERT INTO settings (setting_key, setting_value, description, updated_by_admin_id, updated_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (setting_key) DO UPDATE SET
                        setting_value = EXCLUDED.setting_value,
                        description = COALESCE(EXCLUDED.description, settings.description),
                        updated_by_admin_id = EXCLUDED.updated_by_admin_id,
                        updated_at = CURRENT_TIMESTAMP
                """, (key, str(value), description, admin_id))
            else:
                # Check if exists
                cursor.execute("SELECT id FROM settings WHERE setting_key = ?", (key,))
                if cursor.fetchone():
                    cursor.execute("""
                        UPDATE settings 
                        SET setting_value = ?, updated_by_admin_id = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE setting_key = ?
                    """, (str(value), admin_id, key))
                else:
                    cursor.execute("""
                        INSERT INTO settings (setting_key, setting_value, description, updated_by_admin_id)
                        VALUES (?, ?, ?, ?)
                    """, (key, str(value), description, admin_id))
            
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error setting {key}: {e}")
        return False


def get_all_settings():
    """Get all settings"""
    try:
        return db.execute_query("SELECT * FROM settings ORDER BY setting_key", fetch_all=True)
    except Exception as e:
        logger.error(f"Error getting all settings: {e}")
        return []


def get_domain_price():
    """Get domain price in INR"""
    price = get_setting('domain_price_inr', '166')
    try:
        return int(price)
    except ValueError:
        return 166


def is_payment_enabled():
    """Check if payment is enabled"""
    enabled = get_setting('payment_enabled', 'true')
    return enabled.lower() == 'true'


def _coerce_datetime(value):
    """Convert a value into a datetime instance when possible."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for parser in (
            datetime.fromisoformat,
            lambda v: datetime.strptime(v, '%Y-%m-%d %H:%M:%S'),
            lambda v: datetime.strptime(v, '%Y-%m-%d'),
        ):
            try:
                return parser(value)
            except Exception:
                continue
    return None


def get_subscription_expiry(start_at=None):
    """Return the end of a 1-year subscription window."""
    start_dt = _coerce_datetime(start_at) or datetime.now()
    try:
        return start_dt.replace(year=start_dt.year + 1)
    except ValueError:
        return start_dt + timedelta(days=365)


def get_student_subscription_state(student_id, as_of=None):
    """Return the student's active subscription rows and sync account status."""
    reference_time = _coerce_datetime(as_of) or datetime.now()
    student = db.execute_query(
        'SELECT id, account_status FROM students WHERE id = ?',
        (student_id,),
        fetch_one=True
    )
    if not student:
        return None

    active_domains = db.execute_query(
        '''SELECT sd.id, sd.domain_id, sd.created_at, sd.expires_at, d.domain_name
           FROM student_domains sd
           JOIN domains d ON sd.domain_id = d.id
           WHERE sd.student_id = ?
             AND (sd.expires_at IS NULL OR sd.expires_at > ?)
           ORDER BY d.domain_name''',
        (student_id, reference_time),
        fetch_all=True
    ) or []

    status = (student.get('account_status') or '').lower()
    if active_domains:
        if status == 'expired':
            db.execute_query("UPDATE students SET account_status = 'active' WHERE id = ?", (student_id,))
            status = 'active'
    else:
        if status in ('active', 'approved'):
            db.execute_query("UPDATE students SET account_status = 'expired' WHERE id = ?", (student_id,))
            status = 'expired'

    return {
        'student_id': student_id,
        'account_status': status,
        'active_domains': active_domains,
    }


def generate_short_code(domain_name):
    """Generate a short code from a domain name.
    Examples:
      'Cyber Security' -> 'CS'
      'Web Development' -> 'WD'
      'Full Stack Development' -> 'FSD'
      'AI' -> 'AI'
      'ML' -> 'ML'
      'DevOps' -> 'DO'
      'Data Science' -> 'DS'
    """
    # Known mappings for common domains
    known = {
        'ai': 'AI',
        'ml': 'ML',
        'devops': 'DO',
        'web development': 'WD',
        'data science': 'DS',
        'cyber security': 'CS',
        'cybersecurity': 'CS',
        'full stack development': 'FSD',
        'fullstack development': 'FSD',
        'machine learning': 'ML',
        'artificial intelligence': 'AI',
        'cloud computing': 'CC',
        'internet of things': 'IOT',
        'iot': 'IOT',
        'blockchain': 'BC',
        'digital marketing': 'DM',
        'data analytics': 'DA',
        'python': 'PY',
        'java': 'JV',
        'ui/ux': 'UX',
        'ui ux': 'UX',
    }
    
    lower_name = domain_name.strip().lower()
    if lower_name in known:
        return known[lower_name]
    
    # Auto-generate: take first letter of each word (uppercase)
    words = domain_name.strip().split()
    if len(words) == 1:
        # Single word: take first 2-3 chars
        return domain_name.strip()[:3].upper()
    else:
        # Multiple words: take first letter of each
        return ''.join(w[0] for w in words).upper()
