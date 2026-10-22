from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from database import db, get_bool_literal, get_domain_price, get_subscription_expiry, get_student_subscription_state, is_payment_enabled, get_setting
from utils import generate_otp, send_otp_email, send_registration_confirmation_email, sanitize_input, generate_wapl_id, debug_gmail_connection, log_activity
from extensions import limiter, AUTH_LIMIT, REGISTER_LIMIT, OTP_LIMIT
import secrets
import os
import hmac
import hashlib
import uuid
from functools import wraps

# Check if running in production
def is_production():
    return os.environ.get('FLASK_ENV') == 'production'

# Razorpay Configuration
try:
    import razorpay
    RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID', '')
    RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')
    
    if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        RAZORPAY_ENABLED = True
        print(f"✅ Razorpay initialized (Key: {RAZORPAY_KEY_ID[:12]}...)")
    else:
        razorpay_client = None
        RAZORPAY_ENABLED = False
        print("⚠️ Razorpay keys not configured - payment gateway disabled")
except ImportError:
    razorpay_client = None
    RAZORPAY_ENABLED = False
    RAZORPAY_KEY_ID = ''
    print("⚠️ razorpay package not installed - payment gateway disabled")

auth_bp = Blueprint('auth', __name__)

HR_VERIFICATION_MAX_BYTES = 5 * 1024 * 1024
HR_VERIFICATION_ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png'}


def _get_hr_record(user_id):
    return db.execute_query(
        'SELECT * FROM hrs WHERE user_id = ?',
        (user_id,),
        fetch_one=True
    )


def _get_hr_record_by_email(email):
    return db.execute_query(
        '''SELECT h.*, u.email
           FROM hrs h
           JOIN users u ON h.user_id = u.id
           WHERE u.email = ?''',
        (email,),
        fetch_one=True
    )


def _hr_login_response(hr_status, approved_redirect='/hr/dashboard'):
    if hr_status == 'pending':
        return jsonify({'error': 'Account pending admin approval'}), 403
    if hr_status == 'rejected':
        return jsonify({'error': 'Account rejected. Please contact admin.'}), 403
    return jsonify({'error': 'Account not approved yet'}), 403


def _secure_hr_file_upload(file_storage):
    """Save an HR verification file outside the public uploads tree."""
    if not file_storage or not file_storage.filename:
        return None

    original_name = secure_filename(file_storage.filename)
    ext = os.path.splitext(original_name)[1].lower()
    if ext not in HR_VERIFICATION_ALLOWED_EXTENSIONS:
        return None

    upload_dir = os.path.join(os.getcwd(), 'private_uploads', 'hr_verifications')
    os.makedirs(upload_dir, exist_ok=True)
    unique_name = f"hr_proof_{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(upload_dir, unique_name)
    file_storage.save(file_path)
    return os.path.join('private_uploads', 'hr_verifications', unique_name).replace('\\', '/')

def require_auth(roles=None):
    """Decorator to require authentication and optionally specific roles"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            
            if roles and session.get('role') not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


# ==================== HR AUTH ROUTES ====================


@auth_bp.route('/hr/signup')
def hr_signup_page():
    if 'user_id' in session and session.get('role') == 'hr':
        hr = _get_hr_record(session['user_id'])
        if hr and hr.get('status') == 'approved':
            return redirect('/hr/dashboard')
    return render_template('hr/signup.html')


@auth_bp.route('/hr/login')
def hr_login_page():
    if 'user_id' in session and session.get('role') == 'hr':
        hr = _get_hr_record(session['user_id'])
        if hr and hr.get('status') == 'approved':
            return redirect('/hr/dashboard')
    return render_template('hr/login.html')


@auth_bp.route('/api/hr/register', methods=['POST'])
@limiter.limit(REGISTER_LIMIT)
def hr_register():
    """Register a new HR account with verification proof upload."""
    try:
        if request.content_type and request.content_type.startswith('application/json'):
            data = request.get_json() or {}
            file_storage = None
        else:
            data = request.form.to_dict(flat=True)
            file_storage = request.files.get('verification_proof')

        full_name = sanitize_input((data.get('full_name') or data.get('fullName') or '').strip())
        email = sanitize_input((data.get('email') or '').strip().lower())
        company_name = sanitize_input((data.get('company_name') or data.get('companyName') or '').strip())
        years_raw = (data.get('years_of_experience') or data.get('yearsOfExperience') or '').strip()
        designation = sanitize_input((data.get('designation') or '').strip())
        password = data.get('password', '')

        if not all([full_name, email, company_name, years_raw, designation, password]):
            return jsonify({'error': 'All fields are required'}), 400

        try:
            years_of_experience = int(years_raw)
        except ValueError:
            return jsonify({'error': 'Years of experience must be a valid number'}), 400

        if years_of_experience < 0 or years_of_experience > 60:
            return jsonify({'error': 'Years of experience must be between 0 and 60'}), 400

        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400

        if not file_storage or not file_storage.filename:
            return jsonify({'error': 'Verification proof is required'}), 400

        filename = secure_filename(file_storage.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in HR_VERIFICATION_ALLOWED_EXTENSIONS:
            return jsonify({'error': 'Verification proof must be PDF, JPG, or PNG'}), 400

        file_storage.stream.seek(0, os.SEEK_END)
        file_size = file_storage.stream.tell()
        file_storage.stream.seek(0)
        if file_size > HR_VERIFICATION_MAX_BYTES:
            return jsonify({'error': 'Verification proof must be 5MB or smaller'}), 400

        existing_user = db.execute_query('SELECT id, role FROM users WHERE email = ?', (email,), fetch_one=True)
        if existing_user:
            # If the email already exists as a different role, we can't safely reuse it for HR.
            if (existing_user.get('role') or '').lower() != 'hr':
                return jsonify({'error': 'Email is already registered'}), 400

            # Role is HR, but some older partial registrations can leave a user without an hrs row.
            existing_hr = _get_hr_record(existing_user['id'])
            verification_path = _secure_hr_file_upload(file_storage)
            if not verification_path:
                return jsonify({'error': 'Failed to store verification proof'}), 500

            password_hash = generate_password_hash(password)
            db.execute_query(
                'UPDATE users SET password_hash = ?, is_verified = ? WHERE id = ?',
                (password_hash, True, existing_user['id'])
            )

            if not existing_hr:
                db.execute_query(
                    '''INSERT INTO hrs
                       (user_id, full_name, company_name, years_of_experience, phone, designation,
                        verification_proof_path, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')''',
                    (existing_user['id'], full_name, company_name, years_of_experience, '', designation, verification_path)
                )
            else:
                # Allow a rejected HR to re-apply by overwriting the proof and resetting to pending.
                # Pending/approved accounts remain blocked by the frontend and should not hit this path.
                if (existing_hr.get('status') or '').lower() != 'rejected':
                    return jsonify({'error': 'Email is already registered'}), 400
                db.execute_query(
                    '''UPDATE hrs
                       SET full_name = ?, company_name = ?, years_of_experience = ?, designation = ?,
                           verification_proof_path = ?, status = 'pending', rejection_reason = NULL,
                           reviewed_by_admin_id = NULL, reviewed_at = NULL, rejected_at = NULL
                       WHERE user_id = ?''',
                    (full_name, company_name, years_of_experience, designation, verification_path, existing_user['id'])
                )

            log_activity(
                'hr_registration',
                'auth',
                target_type='hr',
                target_id=existing_user['id'],
                target_name=full_name,
                details='HR registration submitted for admin approval'
            )

            return jsonify({
                'message': 'Your registration is successful. Please wait for admin approval.',
                'redirect': '/hr/login'
            }), 201

        verification_path = _secure_hr_file_upload(file_storage)
        if not verification_path:
            return jsonify({'error': 'Failed to store verification proof'}), 500

        password_hash = generate_password_hash(password)
        user_id = db.execute_query(
            "INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, 'hr', ?)",
            (email, password_hash, True)
        )

        db.execute_query(
            '''INSERT INTO hrs
               (user_id, full_name, company_name, years_of_experience, phone, designation,
                verification_proof_path, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')''',
            (user_id, full_name, company_name, years_of_experience, '', designation, verification_path)
        )

        log_activity(
            'hr_registration',
            'auth',
            target_type='hr',
            target_id=user_id,
            target_name=full_name,
            details='HR registration submitted for admin approval'
        )

        return jsonify({
            'message': 'Your registration is successful. Please wait for admin approval.',
            'redirect': '/hr/login'
        }), 201
    except Exception as e:
        print(f"HR registration error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'An error occurred while registering the HR account'}), 500


@auth_bp.route('/api/hr/login', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def hr_login():
    """HR login with approval status checks."""
    try:
        data = request.get_json() or {}
        email = sanitize_input((data.get('email') or '').strip().lower())
        password = data.get('password', '')

        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400

        user = db.execute_query(
            "SELECT * FROM users WHERE email = ? AND role = 'hr'",
            (email,),
            fetch_one=True
        )

        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid email or password'}), 401

        hr = _get_hr_record(user['id'])
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404

        hr_status = (hr.get('status') or 'pending').lower()
        if hr_status != 'approved':
            return _hr_login_response(hr_status)

        db.execute_query(
            'UPDATE users SET last_login = ? WHERE id = ?',
            (datetime.now(), user['id'])
        )

        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = 'hr'
        session.permanent = True

        log_activity('hr_login', 'auth', target_type='hr', target_id=user['id'], target_name=email)

        return jsonify({
            'message': 'Login successful',
            'role': 'hr',
            'redirect': '/hr/dashboard'
        }), 200
    except Exception as e:
        print(f"HR login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'An error occurred during login'}), 500


# ==================== PAYMENT ROUTES ====================


@auth_bp.route('/api/payment/config', methods=['GET'])
def get_payment_config():
    """Get payment configuration for frontend"""
    # Check both Razorpay SDK availability AND admin setting
    payment_enabled = RAZORPAY_ENABLED and is_payment_enabled()
    
    # Get domain prices for frontend display
    domains = db.execute_query(
        f"SELECT id, domain_name, price FROM domains WHERE is_active = {get_bool_literal(True)} ORDER BY domain_name",
        fetch_all=True
    )
    domain_prices = {d['id']: d.get('price', 0) or 0 for d in domains}
    
    return jsonify({
        'enabled': payment_enabled,
        'key_id': RAZORPAY_KEY_ID if payment_enabled else None,
        'domain_prices': domain_prices,
        'currency': get_setting('currency', 'INR')
    }), 200


@auth_bp.route('/api/payment/create-order', methods=['POST'])
def create_payment_order():
    """Create Razorpay order for domain registration"""
    if not RAZORPAY_ENABLED:
        return jsonify({'error': 'Payment gateway not configured'}), 503
    
    if not is_payment_enabled():
        return jsonify({'error': 'Payment is currently disabled by admin'}), 503
    
    try:
        data = request.get_json()
        domain_ids = data.get('domain_ids', [])
        email = data.get('email', '').strip().lower()
        
        if not domain_ids or len(domain_ids) < 1:
            return jsonify({'error': 'At least one domain must be selected'}), 400
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Calculate total amount based on individual domain prices
        placeholders = ','.join(['?' for _ in domain_ids])
        domains = db.execute_query(
            f"SELECT id, domain_name, price FROM domains WHERE id IN ({placeholders}) AND is_active = {get_bool_literal(True)}",
            tuple(domain_ids),
            fetch_all=True
        )
        
        if len(domains) != len(domain_ids):
            return jsonify({'error': 'One or more selected domains are invalid or inactive'}), 400
        
        # Sum up individual domain prices
        amount_inr = sum(d.get('price', 0) or 0 for d in domains)
        amount_paise = amount_inr * 100
        
        # If total is 0, payment is not required
        if amount_inr == 0:
            return jsonify({
                'payment_required': False,
                'message': 'No payment required for selected domains'
            }), 200
        
        # Razorpay minimum is ₹1 (100 paise)
        if amount_paise < 100:
            return jsonify({'error': f'Minimum order amount is ₹1. Current: ₹{amount_inr}'}), 400
        
        # Create Razorpay order
        order_data = {
            'amount': amount_paise,
            'currency': 'INR',
            'receipt': f'reg_{email[:10]}_{datetime.now().strftime("%Y%m%d%H%M%S")}',
            'notes': {
                'email': email,
                'domain_ids': ','.join(map(str, domain_ids)),
                'domain_count': str(len(domain_ids)),
                'purpose': 'student_registration'
            }
        }
        
        order = razorpay_client.order.create(data=order_data)
        
        # Store order in database
        db.execute_query(
            '''INSERT INTO payments (razorpay_order_id, email, amount, domain_count, status)
               VALUES (?, ?, ?, ?, 'pending')''',
            (order['id'], email, amount_inr, len(domain_ids))
        )
        
        print(f"💳 Payment order created: {order['id']} for {email} ({len(domain_ids)} domains = ₹{amount_inr})")
        
        return jsonify({
            'payment_required': True,
            'order_id': order['id'],
            'amount': amount_inr,
            'amount_paise': amount_paise,
            'currency': 'INR',
            'key_id': RAZORPAY_KEY_ID
        }), 200
        
    except Exception as e:
        print(f"❌ Payment order creation failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to create payment order: {str(e)}'}), 500


@auth_bp.route('/api/payment/verify', methods=['POST'])
def verify_payment():
    """Verify Razorpay payment signature"""
    if not RAZORPAY_ENABLED:
        return jsonify({'error': 'Payment gateway not configured'}), 503
    
    try:
        data = request.get_json()
        razorpay_order_id = data.get('razorpay_order_id', '')
        razorpay_payment_id = data.get('razorpay_payment_id', '')
        razorpay_signature = data.get('razorpay_signature', '')
        
        if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature]):
            return jsonify({'error': 'Missing payment verification data'}), 400
        
        # Verify signature using Razorpay SDK (works correctly for both test and live keys)
        try:
            razorpay_client.utility.verify_payment_signature({
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            })
            print(f"✅ Razorpay signature verified for order: {razorpay_order_id}")
        except Exception as sig_error:
            print(f"❌ Payment signature verification failed for order: {razorpay_order_id} - {sig_error}")
            return jsonify({'error': 'Payment verification failed - invalid signature'}), 400
        
        # Update payment record
        db.execute_query(
            '''UPDATE payments 
               SET razorpay_payment_id = ?, razorpay_signature = ?, status = 'verified', verified_at = ?
               WHERE razorpay_order_id = ?''',
            (razorpay_payment_id, razorpay_signature, datetime.now(), razorpay_order_id)
        )
        
        # Store verified payment in session for registration
        session['verified_payment'] = {
            'order_id': razorpay_order_id,
            'payment_id': razorpay_payment_id,
            'verified_at': datetime.now().isoformat()
        }
        
        print(f"✅ Payment verified: {razorpay_payment_id} for order {razorpay_order_id}")
        
        return jsonify({
            'message': 'Payment verified successfully',
            'payment_id': razorpay_payment_id
        }), 200
        
    except Exception as e:
        print(f"❌ Payment verification failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Payment verification failed: {str(e)}'}), 500


@auth_bp.route('/api/payment/mark-failed', methods=['POST'])
def mark_payment_failed():
    """Mark a payment as failed when user cancels or payment fails"""
    try:
        data = request.get_json()
        razorpay_order_id = data.get('razorpay_order_id', '')
        reason = data.get('reason', 'Payment failed or cancelled')
        
        if not razorpay_order_id:
            return jsonify({'error': 'Order ID is required'}), 400
        
        # Update payment record to failed
        db.execute_query(
            '''UPDATE payments 
               SET status = 'failed', verified_at = ?
               WHERE razorpay_order_id = ? AND status = 'pending' ''',
            (datetime.now(), razorpay_order_id)
        )
        
        print(f"❌ Payment marked as failed: {razorpay_order_id} - {reason}")
        
        return jsonify({
            'message': 'Payment marked as failed',
            'order_id': razorpay_order_id
        }), 200
        
    except Exception as e:
        print(f"❌ Error marking payment failed: {e}")
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/api/auth/register', methods=['POST'])
@limiter.limit(REGISTER_LIMIT)
def register():
    """Student registration with OTP verification - multiple domains support"""
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email', '').strip().lower())
        password = data.get('password', '')
        full_name = sanitize_input(data.get('full_name', '').strip())
        phone = sanitize_input(data.get('phone', '').strip())
        address = sanitize_input(data.get('address', '').strip())
        domain_ids = data.get('domain_ids', [])  # Array of domain IDs
        razorpay_payment_id = data.get('razorpay_payment_id', '')  # Payment ID from frontend
        
        print(f"📝 Registration attempt: email={email}, domains={domain_ids}, razorpay_enabled={RAZORPAY_ENABLED}")
        
        # Validation
        if not all([email, password, full_name, phone]):
            print(f"❌ Registration failed: Missing required fields")
            return jsonify({'error': 'Email, password, full name, and phone are required'}), 400
        
        if not domain_ids or len(domain_ids) == 0:
            print(f"❌ Registration failed: No domains selected")
            return jsonify({'error': 'Please select at least one domain'}), 400
        
        if len(password) < 6:
            print(f"❌ Registration failed: Password too short")
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        subscription_start_at = datetime.now().isoformat()
        
        # Verify payment if Razorpay is enabled AND admin has enabled payments
        if RAZORPAY_ENABLED and is_payment_enabled():
            # Check session for verified payment
            verified_payment = session.get('verified_payment')
            print(f"💳 Payment check: verified_payment={verified_payment}")
            
            if not verified_payment:
                print(f"❌ Registration failed: No verified payment in session")
                return jsonify({'error': 'Payment required. Please complete payment before registration.'}), 402
            
            # Verify the payment matches the email and domain count
            payment_record = db.execute_query(
                '''SELECT * FROM payments WHERE razorpay_order_id = ? AND status = 'verified' ''',
                (verified_payment['order_id'],),
                fetch_one=True
            )
            
            if not payment_record:
                session.pop('verified_payment', None)
                print(f"❌ Registration failed: Payment record not found for order {verified_payment['order_id']}")
                return jsonify({'error': 'Payment not found or not verified. Please try again.'}), 402
            
            if payment_record['email'].lower() != email.lower():
                print(f"❌ Registration failed: Email mismatch - payment={payment_record['email']}, registration={email}")
                return jsonify({'error': 'Payment email does not match registration email'}), 400
            
            if payment_record['domain_count'] != len(domain_ids):
                print(f"❌ Registration failed: Domain count mismatch - payment={payment_record['domain_count']}, selected={len(domain_ids)}")
                return jsonify({'error': f'Payment was for {payment_record["domain_count"]} domain(s), but you selected {len(domain_ids)}'}), 400

            payment_start = payment_record.get('verified_at') or payment_record.get('created_at') or datetime.now()
            subscription_start_at = payment_start.isoformat() if isinstance(payment_start, datetime) else str(payment_start)
            
            print(f"✅ Payment verified for registration: {email} (Payment: {verified_payment['payment_id']})")
        
        # Check if email exists
        existing_user = db.execute_query(
            'SELECT id, is_verified FROM users WHERE email = ?',
            (email,),
            fetch_one=True
        )
        
        if existing_user:
            # ===== CHECK: Block re-registration for active/approved students =====
            if existing_user['is_verified']:
                student_record = db.execute_query(
                    'SELECT account_status, cooldown_until, full_name, wapl_id FROM students WHERE user_id = ?',
                    (existing_user['id'],),
                    fetch_one=True
                )
                # Active or approved students should NOT re-register — warn them
                if student_record and student_record['account_status'] in ('active', 'approved'):
                    wapl_id = student_record.get('wapl_id', '')
                    # Check if they have any domain cooldowns
                    domain_cds = db.execute_query(
                        '''SELECT dc.cooldown_until, d.domain_name
                           FROM domain_cooldowns dc
                           JOIN domains d ON dc.domain_id = d.id
                           WHERE dc.student_id = (SELECT id FROM students WHERE user_id = ?)
                             AND dc.cooldown_until > ?''',
                        (existing_user['id'], datetime.now()),
                        fetch_all=True
                    )
                    if domain_cds:
                        cd_info = '; '.join([
                            f"{cd['domain_name']}: re-apply after {datetime.fromisoformat(cd['cooldown_until']).strftime('%B %d, %Y') if isinstance(cd['cooldown_until'], str) else cd['cooldown_until'].strftime('%B %d, %Y')}"
                            for cd in domain_cds
                        ])
                        return jsonify({
                            'error': f'You already have an active account (WAPL ID: {wapl_id}). '
                                     f'Please log in to your existing account. '
                                     f'Some domains are on cooldown: {cd_info}. '
                                     f'You can retake those exams after the cooldown period.',
                            'has_account': True,
                            'wapl_id': wapl_id
                        }), 409
                    else:
                        return jsonify({
                            'error': f'You already have an active account (WAPL ID: {wapl_id}). '
                                     f'Please log in to your existing account instead of creating a new one.',
                            'has_account': True,
                            'wapl_id': wapl_id
                        }), 409
                # Cooldown check for fully failed students
                elif student_record and student_record['account_status'] == 'failed':
                    cooldown = student_record.get('cooldown_until')
                    if cooldown:
                        if isinstance(cooldown, str):
                            cooldown = datetime.fromisoformat(cooldown)
                        if datetime.now() < cooldown:
                            cooldown_date = cooldown.strftime('%B %d, %Y')
                            print(f"🚫 Registration blocked for {email} - cooldown until {cooldown_date}")
                            return jsonify({
                                'error': f'Your previous application was unsuccessful. You can re-apply after {cooldown_date}.',
                                'cooldown_until': cooldown.strftime('%Y-%m-%d %H:%M:%S'),
                                'blocked': True
                            }), 403
                        else:
                            # Cooldown expired — clean up old records so they can re-register
                            old_student = db.execute_query('SELECT id FROM students WHERE user_id = ?', (existing_user['id'],), fetch_one=True)
                            if old_student:
                                db.execute_query('DELETE FROM student_domains WHERE student_id = ?', (old_student['id'],))
                                db.execute_query('DELETE FROM domain_cooldowns WHERE student_id = ?', (old_student['id'],))
                                try:
                                    db.execute_query('DELETE FROM exam_results WHERE student_id = ?', (old_student['id'],))
                                except Exception:
                                    pass  # Table may not exist yet
                                db.execute_query('DELETE FROM students WHERE id = ?', (old_student['id'],))
                            db.execute_query('DELETE FROM otp_verifications WHERE user_id = ?', (existing_user['id'],))
                            db.execute_query('DELETE FROM users WHERE id = ?', (existing_user['id'],))
                            print(f"🔄 Cooldown expired for {email}, allowing fresh registration")
                            # Fall through to allow registration
                            existing_user = None  # Clear so it doesn't hit the checks below

            # Check if user is orphaned (Zombie user - deleted from students but not users)
            if existing_user:
                is_orphaned = False
                if existing_user['is_verified']:
                    # Get role to check correct profile table
                    user_role_data = db.execute_query('SELECT role FROM users WHERE id = ?', (existing_user['id'],), fetch_one=True)
                    if user_role_data:
                        role = user_role_data['role']
                        profile = None
                        if role == 'student':
                            profile = db.execute_query('SELECT id FROM students WHERE user_id = ?', (existing_user['id'],), fetch_one=True)
                        elif role == 'hr':
                            profile = db.execute_query('SELECT id FROM hrs WHERE user_id = ?', (existing_user['id'],), fetch_one=True)
                        elif role == 'admin':
                            profile = db.execute_query('SELECT id FROM admins WHERE user_id = ?', (existing_user['id'],), fetch_one=True)
                        
                        if not profile:
                            is_orphaned = True

                # If email exists but user never verified OR is orphaned/zombie, allow re-registration
                if (not existing_user['is_verified']) or is_orphaned:
                    # Delete the old account so user can start fresh
                    old_user_id = existing_user['id']
                    # Delete OTP records for this user
                    db.execute_query('DELETE FROM otp_verifications WHERE user_id = ?', (old_user_id,))
                    # Delete the user account
                    db.execute_query('DELETE FROM users WHERE id = ?', (old_user_id,))
                    print(f"🔄 Deleted {'orphaned (zombie)' if is_orphaned else 'abandoned'} registration for {email}, allowing new attempt")
                else:
                    # Email is verified and has a valid profile
                    return jsonify({'error': 'Email already registered'}), 400
        
        # Validate domains exist and are active
        is_active_val = get_bool_literal(True)
        for domain_id in domain_ids:
            domain = db.execute_query(
                f'SELECT id FROM domains WHERE id = ? AND is_active = {is_active_val}',
                (domain_id,),
                fetch_one=True
            )
            
            if not domain:
                return jsonify({'error': f'Invalid or inactive domain selected'}), 400
        
        # Create user account (unverified until OTP is confirmed)
        password_hash = generate_password_hash(password)
        
        sql = 'INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, ?, ?)'
        user_id = db.execute_query(sql, (email, password_hash, 'student', False))
        
        # Store registration data in session for OTP verification
        payment_order_id = None
        if RAZORPAY_ENABLED and session.get('verified_payment'):
            payment_order_id = session['verified_payment'].get('order_id')
        
        session['pending_registration'] = {
            'user_id': user_id,
            'email': email,
            'full_name': full_name,
            'phone': phone,
            'address': address,
            'domain_ids': domain_ids,
            'payment_order_id': payment_order_id,
            'subscription_start_at': subscription_start_at
        }
        
        # Generate OTP
        otp_code = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)
        
        db.execute_query(
            'INSERT INTO otp_verifications (user_id, otp_code, purpose, expires_at) VALUES (?, ?, ?, ?)',
            (user_id, otp_code, 'registration', expires_at)
        )
        
        # Send OTP email via Gmail
        email_sent = send_otp_email(email, otp_code, full_name)

        if not email_sent:
            db.execute_query('DELETE FROM otp_verifications WHERE user_id = ?', (user_id,))
            db.execute_query('DELETE FROM users WHERE id = ?', (user_id,))
            session.pop('pending_registration', None)
            session.pop('verified_payment', None)
            return jsonify({
                'error': 'OTP email could not be delivered. Check SMTP credentials or resend later.'
            }), 500
        
        if not is_production():
            print(f"🔐 OTP for {email}: {otp_code}")  # Dev only
        print(f"Registration initiated for: {email}, User ID: {user_id}, Email sent: {email_sent}")
        
        log_activity('Student registration initiated', 'auth', target_type='student', target_id=user_id, target_name=full_name, details=f'Email: {email}, Domains: {domain_ids}')

        response_data = {
            'message': 'Registration successful. Please verify OTP sent to your email.',
            'user_id': user_id,
            'email_sent': email_sent
        }
        # Only include OTP in response for development
        if not is_production():
            response_data['otp_code'] = otp_code
        
        return jsonify(response_data), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/auth/verify-otp', methods=['POST'])
@limiter.limit(OTP_LIMIT)
def verify_otp():
    """Verify OTP and complete student registration with PENDING status"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        otp_code = data.get('otp_code', '').strip()
        
        print(f"🔍 Verifying OTP: user_id={user_id}, otp_code={otp_code}")
        
        if not all([user_id, otp_code]):
            return jsonify({'error': 'User ID and OTP are required'}), 400
        
        # Verify OTP
        otp_record = db.execute_query(
            '''SELECT * FROM otp_verifications 
               WHERE user_id = ? AND otp_code = ? AND purpose = 'registration' 
               AND is_used = {is_false} AND expires_at > ?'''.format(is_false=get_bool_literal(False)),
            (user_id, otp_code, datetime.now()),
            fetch_one=True
        )
        
        if not otp_record:
            print(f"❌ Invalid or expired OTP for user_id: {user_id}")
            return jsonify({'error': 'Invalid or expired OTP'}), 400
        
        # Mark OTP as used
        is_true_val = get_bool_literal(True)
        db.execute_query(
            f'UPDATE otp_verifications SET is_used = {is_true_val} WHERE id = ?',
            (otp_record['id'],)
        )
        
        # Mark user as verified
        db.execute_query(
            f'UPDATE users SET is_verified = {is_true_val} WHERE id = ?',
            (user_id,)
        )
        
        # Get registration data from session
        registration_data = session.get('pending_registration')
        
        if not registration_data or registration_data.get('user_id') != user_id:
            print(f"❌ Registration data not found in session for user_id: {user_id}")
            return jsonify({'error': 'Registration data not found. Please register again.'}), 400
        
        # Complete student registration
        try:
            # Generate WAPL ID with domain-based code
            domain_ids = registration_data.get('domain_ids', [])
            subscription_start_at = registration_data.get('subscription_start_at')
            wapl_id = generate_wapl_id(domain_ids=domain_ids)
            
            # Create student record with PENDING status (requires admin approval)
            insert_student_sql = '''INSERT INTO students 
                   (user_id, wapl_id, full_name, phone, address, account_status)
                   VALUES (?, ?, ?, ?, ?, ?)'''
            
            student_params = (
                user_id,
                wapl_id,
                registration_data.get('full_name', ''),
                registration_data.get('phone', ''),
                registration_data.get('address', ''),
                'pending'
            )
            
            student_id = db.execute_query(insert_student_sql, student_params)
            
            # Assign multiple domains via junction table
            for domain_id in registration_data.get('domain_ids', []):
                db.execute_query(
                    "INSERT INTO student_domains (student_id, domain_id, expires_at) VALUES (?, ?, ?)",
                    (student_id, domain_id, get_subscription_expiry(subscription_start_at))
                )

            db.execute_query(
                "UPDATE students SET account_status = 'active' WHERE id = ? AND account_status = 'expired'",
                (student_id,)
            )
            
            # Get user email
            email = registration_data.get('email', '')
            full_name = registration_data.get('full_name', '')
            
            # Send confirmation email via Gmail
            if email:
                send_registration_confirmation_email(email, full_name, wapl_id)
            
            # Mark payment as completed if payment was made
            payment_order_id = registration_data.get('payment_order_id')
            if payment_order_id:
                db.execute_query(
                    "UPDATE payments SET status = 'completed' WHERE razorpay_order_id = ?",
                    (payment_order_id,)
                )
                print(f"💳 Payment completed for order: {payment_order_id}")
            
            # Clear session data
            session.pop('pending_registration', None)
            session.pop('verified_payment', None)  # Clear payment verification
            
            log_activity('OTP verified, student registration completed', 'auth', target_type='student', target_id=user_id, target_name=full_name, details=f'WAPL ID: {wapl_id}, Status: pending')

            print(f"✅ Student registered: {email} (WAPL ID: {wapl_id}) - Status: PENDING")
            
        except Exception as e:
            print(f"Error completing registration: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'Failed to complete registration: {str(e)}'}), 500
        
        return jsonify({
            'message': 'Registration complete! Your account is pending admin approval. You will be notified once approved.',
            'wapl_id': wapl_id,
            'status': 'pending'
        }), 200
        
    except Exception as e:
        print(f"OTP verification error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/auth/resend-otp', methods=['POST'])
@limiter.limit(OTP_LIMIT)
def resend_otp():
    """Resend OTP for registration"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400
        
        # Verify user exists
        user = db.execute_query(
            'SELECT id, email FROM users WHERE id = ?',
            (user_id,),
            fetch_one=True
        )
        if not user:
            return jsonify({'error': 'Invalid user'}), 400
        
        # Generate new OTP
        otp_code = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)
        
        # Invalidate old OTPs
        is_true_val = get_bool_literal(True)
        db.execute_query(
            f'UPDATE otp_verifications SET is_used = {is_true_val} WHERE user_id = ? AND purpose = ?',
            (user_id, 'registration')
        )
        
        # Create new OTP
        db.execute_query(
            'INSERT INTO otp_verifications (user_id, otp_code, purpose, expires_at) VALUES (?, ?, ?, ?)',
            (user_id, otp_code, 'registration', expires_at)
        )
        
        # Send OTP email
        email_sent = False
        if user:
            email_sent = send_otp_email(user['email'], otp_code, "User")

        if not email_sent:
            db.execute_query(
                'DELETE FROM otp_verifications WHERE user_id = ? AND purpose = ?',
                (user_id, 'registration')
            )
            return jsonify({'error': 'OTP email could not be delivered. Check SMTP credentials or try again.'}), 500
        
        if not is_production():
            print(f"🔐 NEW OTP for user_id {user_id}: {otp_code}")  # Dev only
        print(f"OTP resent for user_id: {user_id}")
        
        response_data = {'message': 'OTP resent successfully'}
        if not is_production():
            response_data['otp_code'] = otp_code
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Resend OTP error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/auth/login', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def login():
    """Login with student status check"""
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email', '').strip().lower())
        password = data.get('password', '')
        
        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Get user
        user = db.execute_query(
            'SELECT * FROM users WHERE email = ?',
            (email,),
            fetch_one=True
        )
        
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        if not user['is_verified']:
            return jsonify({'error': 'Please verify your email first'}), 403
        
        # Security: Prevent admins from logging in via standard portal
        if user['role'] == 'admin':
            return jsonify({'error': 'Admins must use the secure login portal'}), 403

        hr = None

        # Enforce student account status and subscription validity
        if user['role'] == 'student':
            student = db.execute_query(
                'SELECT id, account_status, cooldown_until FROM students WHERE user_id = ?',
                (user['id'],),
                fetch_one=True
            )
            if not student:
                return jsonify({'error': 'Student profile not found'}), 404

            subscription_state = get_student_subscription_state(student['id'])
            if subscription_state:
                student['account_status'] = subscription_state['account_status']
            
            status = student['account_status']
            
            if status == 'pending':
                return jsonify({'error': 'Your account is pending admin approval. You will be notified once approved.'}), 403
            elif status == 'failed':
                cooldown = student.get('cooldown_until')
                if cooldown:
                    if isinstance(cooldown, str):
                        cooldown = datetime.fromisoformat(cooldown)
                    cooldown_date = cooldown.strftime('%B %d, %Y')
                    return jsonify({'error': f'You did not pass the assessment exam. You can re-apply after {cooldown_date}.'}), 403
                return jsonify({'error': 'You did not pass the assessment exam. Please contact admin.'}), 403
            elif status == 'suspended':
                return jsonify({'error': 'Your account has been suspended. Please contact the administrator.'}), 403
            elif status == 'revoked':
                return jsonify({'error': 'Your account access has been revoked. Please contact the administrator.'}), 403
            elif status == 'expired':
                return jsonify({'error': 'Your subscription has expired. Please renew your domain payment to continue access.'}), 403
            elif status == 'approved':
                # Approved students can log in but are redirected to exam page
                pass
            elif status != 'active':
                return jsonify({'error': f'Account status is {status}. Please contact admin.'}), 403
        elif user['role'] == 'hr':
            hr = _get_hr_record(user['id'])
            if not hr:
                return jsonify({'error': 'HR profile not found'}), 404

            hr_status = (hr.get('status') or 'pending').lower()
            if hr_status == 'pending':
                return jsonify({'error': 'Account pending admin approval'}), 403
            if hr_status == 'rejected':
                return jsonify({'error': 'Account rejected. Please contact admin.'}), 403
            if hr_status != 'approved':
                return jsonify({'error': f'Account status is {hr_status}. Please contact admin.'}), 403

        # Update last login
        db.execute_query(
            'UPDATE users SET last_login = ? WHERE id = ?',
            (datetime.now(), user['id'])
        )
        
        # Set session
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = user['role']
        session.permanent = True
        
        log_activity('Login successful', 'auth', target_type=user['role'], target_id=user['id'], target_name=email)

        # Redirect based on role
        # For approved students, redirect to exam page instead of dashboard
        if user['role'] == 'student' and student and student['account_status'] == 'approved':
            redirect_url = '/exam'
        elif user['role'] == 'hr':
            redirect_url = '/hr/dashboard'
        else:
            redirect_urls = {
                'student': '/student/dashboard',
                'admin': '/secure-admin-panel/wapl/dashboard'
            }
            redirect_url = redirect_urls.get(user['role'], '/')
        
        return jsonify({
            'message': 'Login successful',
            'role': user['role'],
            'redirect': redirect_url
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/admin/login', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def admin_login():
    """Admin login"""
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email', '').strip().lower())
        password = data.get('password', '')
        
        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Get admin user
        user = db.execute_query(
            'SELECT * FROM users WHERE email = ? AND role = ?',
            (email, 'admin'),
            fetch_one=True
        )
        
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Get admin details including super admin status
        admin = db.execute_query(
            'SELECT is_super_admin, is_owner FROM admins WHERE user_id = ?',
            (user['id'],),
            fetch_one=True
        )
        
        # Update last login
        db.execute_query(
            'UPDATE users SET last_login = ? WHERE id = ?',
            (datetime.now(), user['id'])
        )
        
        # Set session with super admin flag
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = 'admin'
        session['is_super_admin'] = bool(admin['is_super_admin']) if admin else False
        session['is_owner'] = bool(admin['is_owner']) if admin else False
        session.permanent = True
        
        log_activity('Admin login successful', 'auth', target_type='admin', target_id=user['id'], target_name=email, details=f'Super admin: {session["is_super_admin"]}')

        return jsonify({
            'message': 'Admin login successful',
            'is_super_admin': session['is_super_admin'],
            'is_owner': session['is_owner'],
            'redirect': '/secure-admin-panel/wapl/dashboard'
        }), 200
        
    except Exception as e:
        print(f"Admin login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout"""
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@auth_bp.route('/login')
def login_page():
    return render_template('login.html')

@auth_bp.route('/register')
def register_page():
    return render_template('register.html')

@auth_bp.route('/verify-otp')
def verify_otp_page():
    return render_template('verify_otp.html')

@auth_bp.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')

@auth_bp.route('/api/auth/forgot-password', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def forgot_password():
    """Forgot password - send OTP"""
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email', '').strip().lower())
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        user = db.execute_query(
            'SELECT id FROM users WHERE email = ?',
            (email,),
            fetch_one=True
        )
        
        if not user:
            # Don't reveal if email exists
            return jsonify({'message': 'If email exists, OTP sent'}), 200
        
        # Generate OTP for password reset
        otp_code = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)
        
        # Invalidate old password reset OTPs for this user
        is_true_val = get_bool_literal(True)
        db.execute_query(
            f"UPDATE otp_verifications SET is_used = {is_true_val} WHERE user_id = ? AND purpose = 'password_reset'",
            (user['id'],)
        )
        
        db.execute_query(
            'INSERT INTO otp_verifications (user_id, otp_code, purpose, expires_at) VALUES (?, ?, ?, ?)',
            (user['id'], otp_code, 'password_reset', expires_at)
        )
        
        email_sent = send_otp_email(email, otp_code, "User")  # Name not available in password reset flow

        if not email_sent:
            db.execute_query(
                'DELETE FROM otp_verifications WHERE user_id = ? AND purpose = ?',
                (user['id'], 'password_reset')
            )
            return jsonify({'error': 'OTP email could not be delivered. Check SMTP credentials or try again.'}), 500
        
        log_activity('Password reset requested', 'auth', target_type='user', target_id=user['id'], target_name=email)

        if not is_production():
            print(f"🔐 Password Reset OTP for {email}: {otp_code}")  # Dev only
        
        response_data = {'message': 'If email exists, OTP sent'}
        if not is_production():
            response_data['otp_code'] = otp_code
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Forgot password error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/api/auth/reset-password', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def reset_password():
    """Reset password with OTP"""
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email', '').strip().lower())
        otp_code = data.get('otp_code', '').strip()
        new_password = data.get('new_password', '')

        if not all([email, otp_code, new_password]):
            return jsonify({'error': 'Email, OTP, and new password are required'}), 400
            
        if len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        # Get user
        user = db.execute_query(
            'SELECT id FROM users WHERE email = ?',
            (email,),
            fetch_one=True
        )

        if not user:
             return jsonify({'error': 'User not found'}), 404

        # Verify OTP
        is_false_val = get_bool_literal(False)
        otp_record = db.execute_query(
            f'''SELECT * FROM otp_verifications 
               WHERE user_id = ? AND otp_code = ? AND purpose = 'password_reset' 
               AND is_used = {is_false_val} AND expires_at > ?''',
            (user['id'], otp_code, datetime.now()),
            fetch_one=True
        )

        if not otp_record:
            return jsonify({'error': 'Invalid or expired OTP'}), 400

        # Mark OTP as used
        is_true_val = get_bool_literal(True)
        db.execute_query(
            f'UPDATE otp_verifications SET is_used = {is_true_val} WHERE id = ?',
            (otp_record['id'],)
        )

        # Update password
        new_password_hash = generate_password_hash(new_password)
        db.execute_query(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_password_hash, user['id'])
        )

        log_activity('Password reset completed', 'auth', target_type='user', target_id=user['id'], target_name=email)

        return jsonify({'message': 'Password reset successful. Please login.'}), 200


    except Exception as e:
        print(f"Reset password error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/api/debug/email', methods=['POST'])
def debug_email():
    """Debug email configuration - development only"""
    if is_production():
        return jsonify({'error': 'Not available in production'}), 403
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
            
        result = debug_gmail_connection(email)
        
        if result['success']:
            return jsonify({'message': 'Email sent successfully', 'details': result}), 200
        else:
            return jsonify({'error': 'Email test failed', 'details': result}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
