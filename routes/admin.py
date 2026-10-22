from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from database import db, get_agg_func, get_bool_literal, get_bool_value, get_setting, set_setting, get_all_settings, get_domain_price, get_subscription_expiry, get_student_subscription_state
from utils import (generate_otp, generate_wapl_id, sanitize_input, send_account_activation_email,
    send_role_otp_email, _should_use_console_email_mode,
    get_student_notification_info, send_student_status_change_email,
    send_student_hr_assigned_email, send_student_hr_unassigned_email,
    send_student_certificate_email, send_student_domain_update_email,
    log_activity)
from extensions import limiter, AUTH_LIMIT
from functools import wraps
import json
import os
import csv
import io
import uuid
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side


admin_bp = Blueprint('admin', __name__)
ADMIN_HR_PROOF_MAX_BYTES = 5 * 1024 * 1024
ADMIN_HR_PROOF_ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png'}


def _save_admin_hr_proof(file_storage):
    """Persist an admin verification proof file outside public uploads."""
    if not file_storage or not file_storage.filename:
        return None

    filename = secure_filename(file_storage.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ADMIN_HR_PROOF_ALLOWED_EXTENSIONS:
        return None

    upload_dir = os.path.join(os.getcwd(), 'private_uploads', 'admin_hr_verifications')
    os.makedirs(upload_dir, exist_ok=True)
    unique_name = f"admin_hr_proof_{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(upload_dir, unique_name)
    file_storage.save(file_path)
    return os.path.join('private_uploads', 'admin_hr_verifications', unique_name).replace('\\', '/')


# ==================== DECORATORS ====================


def require_admin_auth(f):
    """Require any admin (super or regular)"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            if request.path.startswith('/api'):
                return jsonify({'error': 'Admin access required'}), 403
            return redirect(url_for('admin.admin_login_page'))
        return f(*args, **kwargs)
    return wrapper


def require_super_admin_auth(f):
    """Require a super admin or owner."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            if request.path.startswith('/api'):
                return jsonify({'error': 'Admin access required'}), 403
            return redirect(url_for('admin.admin_login_page'))
        
        if not session.get('is_super_admin', False) and not session.get('is_owner', False):
            if request.path.startswith('/api'):
                return jsonify({'error': 'Super admin access required'}), 403
            return jsonify({'error': 'Insufficient permissions - Super admin only'}), 403
        
        return f(*args, **kwargs)
    return wrapper


# ==================== AUTH ROUTES ====================


@admin_bp.route('/api/auth/logout', methods=['POST', 'GET'])
def logout():
    """Logout - clears session"""
    try:
        session.clear()
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/secure-admin-panel/wapl/logout')
def logout_redirect():
    """Logout page - clears session and redirects"""
    log_activity('admin_logout', 'auth')
    session.clear()
    return redirect('/secure-admin-panel/wapl/login')


# ==================== PAGE ROUTES ====================


@admin_bp.route('/secure-admin-panel/wapl/login')
def admin_login_page():
    """Admin login page"""
    if 'user_id' in session and session.get('role') == 'admin':
        return redirect('/secure-admin-panel/wapl/dashboard')
    return render_template('admin/login.html')


@admin_bp.route('/secure-admin-panel/wapl/forgot-password')
def admin_forgot_password_page():
    """Admin forgot password page"""
    return render_template('admin/forgot_password.html')


@admin_bp.route('/secure-admin-panel/wapl/reset-password')
def admin_reset_password_page():
    """Admin reset password page"""
    return render_template('admin/reset_password.html')


@admin_bp.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login API"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = db.execute_query(
            "SELECT * FROM users WHERE email = ? AND role = 'admin'",
            (email,),
            fetch_one=True
        )
        
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        admin = db.execute_query(
            "SELECT * FROM admins WHERE user_id = ?",
            (user['id'],),
            fetch_one=True
        )
        
        if not admin:
            return jsonify({'error': 'Admin profile not found'}), 404
        
        session['user_id'] = user['id']
        session['role'] = 'admin'
        session['email'] = user['email']
        session['is_super_admin'] = bool(admin['is_super_admin'])
        session['is_owner'] = bool(admin['is_owner'])
        
        db.execute_query(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now(), user['id'])
        )
        
        log_activity('admin_login', 'auth', target_type='admin', target_id=user['id'], target_name=user['email'])
        
        return jsonify({
            'message': 'Login successful',
            'redirect': '/secure-admin-panel/wapl/dashboard',
            'is_super_admin': bool(admin['is_super_admin']),
            'is_owner': bool(admin['is_owner'])
        }), 200
        
    except Exception as e:
        print(f"Admin login error: {e}")
        return jsonify({'error': 'An error occurred during login'}), 500


@admin_bp.route('/api/admin/forgot-password', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def admin_forgot_password():
    """Send password reset OTP to admin/super admin via email"""
    try:
        data = request.get_json()
        email = sanitize_input((data.get('email') or '').strip().lower())

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        admin_user = db.execute_query(
            '''SELECT u.id AS user_id,
                      u.email,
                      COALESCE(a.full_name, 'Admin') AS full_name,
                      COALESCE(a.is_super_admin, 0) AS is_super_admin
               FROM users u
               LEFT JOIN admins a ON a.user_id = u.id
               WHERE u.email = ? AND u.role = 'admin' ''',
            (email,),
            fetch_one=True
        )

        if not admin_user:
            response = jsonify({'message': 'If the admin account exists, a reset OTP has been sent'})
            response.headers['Cache-Control'] = 'no-store'
            return response, 200

        otp_code = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)
        is_true_val = get_bool_literal(True)

        db.execute_query(
            f"UPDATE otp_verifications SET is_used = {is_true_val} WHERE user_id = ? AND purpose = 'password_reset'",
            (admin_user['user_id'],)
        )

        db.execute_query(
            'INSERT INTO otp_verifications (user_id, otp_code, purpose, expires_at) VALUES (?, ?, ?, ?)',
            (admin_user['user_id'], otp_code, 'password_reset', expires_at)
        )

        display_name = admin_user['full_name'] if admin_user.get('full_name') else 'Admin'
        role_label = 'Super Admin' if admin_user.get('is_super_admin') else 'Admin'
        email_sent = send_role_otp_email(
            admin_user['email'],
            otp_code,
            full_name=display_name,
            subject=f'WAPL {role_label} Password Reset OTP',
            greeting='Hello',
            intro_line=f'Your {role_label.lower()} password reset OTP is:',
            footer_line='If you did not request this password reset, you can safely ignore this email.'
        )

        if not email_sent:
            return jsonify({
                'error': 'OTP was generated but email delivery failed. Check GMAIL_USER, GMAIL_APP_PASSWORD, or RESEND_API_KEY.'
            }), 500

        log_activity(
            'Admin password reset requested',
            'auth',
            target_type='admin',
            target_id=admin_user['user_id'],
            target_name=admin_user['email'],
            details=f'Role: {role_label}'
        )

        response_data = {'message': 'If the admin account exists, a reset OTP has been sent'}
        if os.environ.get('FLASK_ENV') != 'production':
            response_data['otp_code'] = otp_code
            response_data['dev_note'] = 'Development OTP response enabled. Use this code if email is delayed.'

        if os.environ.get('FLASK_ENV') != 'production':
            print(f"🔐 Admin Password Reset OTP for {email}: {otp_code}")

        response = jsonify(response_data)
        response.headers['Cache-Control'] = 'no-store'
        return response, 200

    except Exception as e:
        print(f"Admin forgot password error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/reset-password', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def admin_reset_password():
    """Reset admin or super admin password using OTP"""
    try:
        data = request.get_json()
        email = sanitize_input((data.get('email') or '').strip().lower())
        otp_code = (data.get('otp_code') or '').strip()
        new_password = data.get('new_password', '')

        if not all([email, otp_code, new_password]):
            return jsonify({'error': 'Email, OTP, and new password are required'}), 400

        if len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        admin_user = db.execute_query(
            '''SELECT u.id AS user_id, u.email
               FROM users u
               WHERE u.email = ? AND u.role = 'admin' ''',
            (email,),
            fetch_one=True
        )

        if not admin_user:
            return jsonify({'error': 'Admin account not found'}), 404

        otp_record = db.execute_query(
            f'''SELECT * FROM otp_verifications
               WHERE user_id = ? AND otp_code = ? AND purpose = 'password_reset'
               AND is_used = {get_bool_literal(False)} AND expires_at > ?''',
            (admin_user['user_id'], otp_code, datetime.now()),
            fetch_one=True
        )

        if not otp_record:
            return jsonify({'error': 'Invalid or expired OTP'}), 400

        db.execute_query(
            f'UPDATE otp_verifications SET is_used = {get_bool_literal(True)} WHERE id = ?',
            (otp_record['id'],)
        )

        new_password_hash = generate_password_hash(new_password)
        db.execute_query(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_password_hash, admin_user['user_id'])
        )

        log_activity('Admin password reset completed', 'auth', target_type='admin', target_id=admin_user['user_id'], target_name=email)

        return jsonify({'message': 'Password reset successful. Please login again.'}), 200

    except Exception as e:
        print(f"Admin reset password error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/secure-admin-panel/wapl/dashboard')
@require_admin_auth
def admin_dashboard():
    """Admin dashboard page"""
    return render_template('admin/dashboard.html')


@admin_bp.route('/secure-admin-panel/wapl/students')
@require_admin_auth
def admin_students():
    """Students management page"""
    return render_template('admin/students.html')


@admin_bp.route('/secure-admin-panel/wapl/add-student')
@require_admin_auth
def add_student_page():
    """Add student page"""
    return render_template('admin/add_student.html')


@admin_bp.route('/secure-admin-panel/wapl/bulk-upload-students')
@require_admin_auth
def bulk_upload_students_page():
    """Bulk student upload page"""
    return render_template('admin/bulk_upload_students.html')


@admin_bp.route('/api/admin/students/bulk-upload', methods=['POST'])
@require_admin_auth
def bulk_upload_students():
    """Bulk upload students from CSV/Excel file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400

        filename = file.filename.lower()
        if not (filename.endswith('.csv') or filename.endswith('.xlsx') or filename.endswith('.xls')):
            return jsonify({'error': 'Only CSV and Excel (.xlsx/.xls) files are accepted'}), 400

        default_password = request.form.get('defaultPassword', '').strip()
        default_status = request.form.get('defaultStatus', 'active').strip()
        if default_status not in ('active', 'approved'):
            default_status = 'active'

        # Parse the file
        rows = []
        if filename.endswith('.csv'):
            import io as _io
            stream = _io.StringIO(file.stream.read().decode('utf-8-sig'))
            reader = csv.DictReader(stream)
            for row in reader:
                rows.append({k.strip().lower(): (v.strip() if v else '') for k, v in row.items()})
        else:
            from openpyxl import load_workbook
            wb = load_workbook(file, read_only=True)
            ws = wb.active
            headers = []
            for idx, cell in enumerate(next(ws.iter_rows(min_row=1, max_row=1, values_only=True))):
                headers.append(str(cell).strip().lower() if cell else f'col{idx}')
            # Fallback: if iter_rows returned a single tuple, handle properly
            if not headers:
                return jsonify({'error': 'Excel file has no headers'}), 400
            for row in ws.iter_rows(min_row=2, values_only=True):
                row_dict = {}
                for i, val in enumerate(row):
                    if i < len(headers):
                        row_dict[headers[i]] = str(val).strip() if val is not None else ''
                if any(row_dict.values()):
                    rows.append(row_dict)
            wb.close()

        if not rows:
            return jsonify({'error': 'File is empty or has no data rows'}), 400

        # Fetch all active domains for matching
        all_domains = db.execute_query('SELECT id, domain_name FROM domains WHERE is_active = ?', (True,), fetch_all=True)
        domain_map = {d['domain_name'].strip().lower(): d['id'] for d in all_domains}

        results = {'created': 0, 'skipped': 0, 'errors': [], 'created_students': []}

        for row_idx, row in enumerate(rows, start=2):
            # Flexible column name mapping
            email = (row.get('email', '') or row.get('e-mail', '') or row.get('email address', '')).strip().lower()
            full_name = (row.get('full name', '') or row.get('fullname', '') or row.get('name', '') or row.get('student name', '')).strip()
            phone = (row.get('phone', '') or row.get('mobile', '') or row.get('phone number', '') or row.get('contact', '')).strip()
            address = (row.get('address', '') or '').strip()
            password = (row.get('password', '') or default_password or '').strip()
            domains_raw = (row.get('domains', '') or row.get('domain', '') or '').strip()

            # Validate required fields
            if not email:
                results['errors'].append(f'Row {row_idx}: Missing email')
                results['skipped'] += 1
                continue
            if not full_name:
                results['errors'].append(f'Row {row_idx}: Missing name for {email}')
                results['skipped'] += 1
                continue
            if not phone:
                results['errors'].append(f'Row {row_idx}: Missing phone for {email}')
                results['skipped'] += 1
                continue
            if not password or len(password) < 6:
                results['errors'].append(f'Row {row_idx}: Password missing or too short (<6 chars) for {email}')
                results['skipped'] += 1
                continue

            # Parse domains
            domain_ids = []
            if domains_raw:
                domain_names = [d.strip().lower() for d in domains_raw.split(',') if d.strip()]
                for dn in domain_names:
                    # Try exact match first, then partial
                    did = domain_map.get(dn)
                    if not did:
                        for dname, d_id in domain_map.items():
                            if dn in dname or dname in dn:
                                did = d_id
                                break
                    if did:
                        domain_ids.append(did)
                    else:
                        results['errors'].append(f'Row {row_idx}: Unknown domain "{dn}" for {email} (skipped domain)')

            if not domain_ids:
                results['errors'].append(f'Row {row_idx}: No valid domains for {email}')
                results['skipped'] += 1
                continue

            # Check if email already exists
            existing_user = db.execute_query(
                'SELECT id FROM users WHERE email = ?', (email,), fetch_one=True
            )
            if existing_user:
                existing_student = db.execute_query(
                    'SELECT id FROM students WHERE user_id = ?', (existing_user['id'],), fetch_one=True
                )
                if existing_student:
                    results['errors'].append(f'Row {row_idx}: {email} already has an account (skipped)')
                    results['skipped'] += 1
                    continue

            # Create user
            try:
                password_hash = generate_password_hash(password)
                if existing_user:
                    user_id = existing_user['id']
                    db.execute_query(
                        'UPDATE users SET password_hash = ?, is_verified = ? WHERE id = ?',
                        (password_hash, True, user_id)
                    )
                else:
                    user_id = db.execute_query(
                        'INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, ?, ?)',
                        (email, password_hash, 'student', True)
                    )

                wapl_id = generate_wapl_id(domain_ids=domain_ids)

                student_id = db.execute_query(
                    '''INSERT INTO students
                       (user_id, wapl_id, full_name, phone, address, account_status, registration_date)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (user_id, wapl_id, full_name, phone, address, default_status, datetime.now())
                )

                for did in domain_ids:
                    db.execute_query(
                        'INSERT INTO student_domains (student_id, domain_id, expires_at) VALUES (?, ?, ?)',
                        (student_id, did, get_subscription_expiry(datetime.now()))
                    )

                results['created'] += 1
                results['created_students'].append({
                    'email': email,
                    'name': full_name,
                    'wapl_id': wapl_id,
                    'domains': len(domain_ids)
                })
            except Exception as row_err:
                results['errors'].append(f'Row {row_idx}: Error creating {email} - {str(row_err)}')
                results['skipped'] += 1

        log_activity('bulk_upload_students', 'student',
                     details=f'Uploaded {results["created"]} students, {results["skipped"]} skipped from {file.filename}')

        return jsonify({
            'message': f'Bulk upload complete: {results["created"]} created, {results["skipped"]} skipped',
            'created': results['created'],
            'skipped': results['skipped'],
            'errors': results['errors'][:50],  # limit error list
            'created_students': results['created_students']
        }), 200

    except UnicodeDecodeError:
        return jsonify({'error': 'File encoding error. Please save as UTF-8 CSV or use .xlsx format.'}), 400
    except Exception as e:
        print(f"❌ Bulk upload error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/students/bulk-upload/template', methods=['GET'])
@require_admin_auth
def download_bulk_template():
    """Download a CSV template for bulk upload"""
    all_domains = db.execute_query('SELECT domain_name FROM domains WHERE is_active = ?', (True,))
    domain_names = ', '.join([d['domain_name'] for d in all_domains]) if all_domains else 'Web Development, ML, DevOps'

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Full Name', 'Email', 'Phone', 'Address', 'Password', 'Domains'])
    writer.writerow(['John Doe', 'john@example.com', '9876543210', '123 Main St', 'pass1234', domain_names])
    writer.writerow(['Jane Smith', 'jane@example.com', '9876543211', '456 Oak Ave', 'pass1234', domain_names])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=bulk_upload_template.csv'}
    )


@admin_bp.route('/secure-admin-panel/wapl/student/<int:student_id>')
@require_admin_auth
def student_detail_page(student_id):
    """Student detail view page"""
    return render_template('admin/student_detail.html')


@admin_bp.route('/secure-admin-panel/wapl/hrs')
@require_admin_auth
def admin_hrs():
    """HRs management page"""
    return render_template('admin/hrs.html')


@admin_bp.route('/secure-admin-panel/wapl/hr/<int:hr_id>')
@require_admin_auth
def admin_hr_detail(hr_id):
    """HR detail view page"""
    return render_template('admin/hr_detail.html', hr_id=hr_id)


@admin_bp.route('/secure-admin-panel/wapl/assign-students')
@require_admin_auth
def admin_assign_students():
    """Assign students to HR page"""
    return render_template('admin/assign_students.html')


@admin_bp.route('/secure-admin-panel/wapl/domains')
@require_super_admin_auth
def admin_domains():
    """Domains management page - Super Admin only"""
    return render_template('admin/domains.html')


@admin_bp.route('/secure-admin-panel/wapl/certificates')
@require_admin_auth
def admin_certificates():
    """Certificates management page"""
    return render_template('admin/certificates.html')


@admin_bp.route('/secure-admin-panel/wapl/recruitment')
@require_admin_auth
def admin_recruitment():
    """Recruitment management page"""
    return render_template('admin/recruitment.html')


@admin_bp.route('/secure-admin-panel/wapl/admins')
@require_super_admin_auth
def admin_admins_page():
    """Admin management page - Super Admin only"""
    return render_template('admin/admins.html')


@admin_bp.route('/secure-admin-panel/wapl/payments')
@require_admin_auth
def admin_payments_page():
    """Payments management page"""
    return render_template('admin/payments.html')


@admin_bp.route('/secure-admin-panel/wapl/settings')
@require_super_admin_auth
def admin_settings_page():
    """Settings page - Super Admin only"""
    admin_email = session.get('email', '')
    return render_template('admin/settings.html', admin_email=admin_email)


@admin_bp.route('/secure-admin-panel/wapl/hr-approvals')
@require_admin_auth
def admin_hr_approvals_page():
    """HR profile change approvals page"""
    return render_template('admin/hr_approvals.html')


@admin_bp.route('/secure-admin-panel/wapl/reports')
@require_admin_auth
def admin_reports_page():
    """Reports & Export page"""
    return render_template('admin/reports.html')


# ==================== API ROUTES ====================


@admin_bp.route('/api/admin/check-super-admin', methods=['GET'])
@require_admin_auth
def check_super_admin():
    """Check if current admin is super admin"""
    return jsonify({'is_super_admin': session.get('is_super_admin', False)}), 200


@admin_bp.route('/api/admin/dashboard/stats', methods=['GET'])
@require_admin_auth
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        total_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students",
            fetch_one=True
        )
        
        active_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE account_status = 'active'",
            fetch_one=True
        )
        
        pending_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE account_status = 'pending'",
            fetch_one=True
        )
        
        suspended_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE account_status = 'suspended'",
            fetch_one=True
        )
        
        total_hrs = db.execute_query(
            "SELECT COUNT(*) as count FROM hrs",
            fetch_one=True
        )
        
        total_certificates = db.execute_query(
            "SELECT COUNT(*) as count FROM certificates",
            fetch_one=True
        )
        
        is_active_val = get_bool_literal(True)
        total_domains = db.execute_query(
            f"SELECT COUNT(*) as count FROM domains WHERE is_active = {is_active_val}",
            fetch_one=True
        )
        
        assigned_students = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE assigned_hr_id IS NOT NULL",
            fetch_one=True
        )
        
        return jsonify({
            'total_students': total_students['count'] if total_students else 0,
            'active_students': active_students['count'] if active_students else 0,
            'pending_students': pending_students['count'] if pending_students else 0,
            'suspended_students': suspended_students['count'] if suspended_students else 0,
            'total_hrs': total_hrs['count'] if total_hrs else 0,
            'total_certificates': total_certificates['count'] if total_certificates else 0,
            'total_domains': total_domains['count'] if total_domains else 0,
            'assigned_students': assigned_students['count'] if assigned_students else 0
        }), 200
        
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== PAYMENTS MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/payments', methods=['GET'])
@require_admin_auth
def get_all_payments():
    """Get all payments with student information"""
    try:
        payments = db.execute_query("""
            SELECT 
                p.*,
                s.wapl_id,
                s.full_name as student_name,
                s.phone as student_phone,
                u.email as student_email
            FROM payments p
            LEFT JOIN users u ON p.email = u.email
            LEFT JOIN students s ON u.id = s.user_id
            ORDER BY p.created_at DESC
        """, fetch_all=True)
        
        # Convert datetime objects to strings for JSON serialization
        for payment in payments:
            if payment.get('created_at'):
                payment['created_at'] = str(payment['created_at'])
            if payment.get('verified_at'):
                payment['verified_at'] = str(payment['verified_at'])
        
        return jsonify(payments), 200
    except Exception as e:
        print(f"Error getting payments: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/payments/stats', methods=['GET'])
@require_admin_auth
def get_payment_stats():
    """Get payment statistics"""
    try:
        # Total payments
        total_result = db.execute_query(
            "SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total FROM payments",
            fetch_one=True
        )
        
        # Completed payments
        completed_result = db.execute_query(
            "SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'completed'",
            fetch_one=True
        )
        
        # Pending payments
        pending_result = db.execute_query(
            "SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'pending'",
            fetch_one=True
        )
        
        # Verified but not completed
        verified_result = db.execute_query(
            "SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'verified'",
            fetch_one=True
        )
        
        # Failed payments
        failed_result = db.execute_query(
            "SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'failed'",
            fetch_one=True
        )
        
        return jsonify({
            'total_payments': total_result['count'],
            'total_amount': total_result['total'],
            'completed_count': completed_result['count'],
            'completed_amount': completed_result['total'],
            'pending_count': pending_result['count'],  
            'pending_amount': pending_result['total'],
            'verified_count': verified_result['count'],
            'verified_amount': verified_result['total'],
            'failed_count': failed_result['count'],
            'failed_amount': failed_result['total']
        }), 200
    except Exception as e:
        print(f"Error getting payment stats: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== SETTINGS MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/settings', methods=['GET'])
@require_super_admin_auth
def get_settings():
    """Get all settings - Super Admin only"""
    try:
        settings = get_all_settings()
        # Convert to dict format for easier frontend usage
        settings_dict = {s['setting_key']: s['setting_value'] for s in settings}
        return jsonify({
            'settings': settings_dict,
            'settings_list': settings
        }), 200
    except Exception as e:
        print(f"Error getting settings: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/settings', methods=['POST'])
@require_super_admin_auth
def update_settings():
    """Update settings - Super Admin only"""
    try:
        data = request.get_json()
        admin_id = session.get('user_id')
        
        updated = []
        for key, value in data.items():
            if set_setting(key, value, admin_id=admin_id):
                updated.append(key)
        
        log_activity('update_settings', 'settings', details=f'Updated: {", ".join(updated)}')
        
        return jsonify({
            'message': 'Settings updated successfully',
            'updated': updated
        }), 200
    except Exception as e:
        print(f"Error updating settings: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/settings/pricing', methods=['GET'])
@require_admin_auth
def get_pricing_settings():
    """Get pricing settings - any admin can view"""
    try:
        return jsonify({
            'domain_price_inr': get_domain_price(),
            'payment_enabled': get_setting('payment_enabled', 'true').lower() == 'true',
            'currency': get_setting('currency', 'INR')
        }), 200
    except Exception as e:
        print(f"Error getting pricing: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== ADMIN MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/admins', methods=['GET'])
@require_super_admin_auth
def get_admins():
    """Get all admins - Super Admin only"""
    try:
        admins = db.execute_query("""
            SELECT 
                a.*,
                u.email,
                u.last_login,
                creator.full_name as created_by_name
            FROM admins a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN admins creator ON a.created_by_admin_id = creator.id
            ORDER BY a.is_super_admin DESC, a.full_name
        """, fetch_all=True)
        
        return jsonify(admins), 200
    except Exception as e:
        print(f"Error getting admins: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/admin/create', methods=['POST'])
@require_super_admin_auth
def create_admin():
    """Create new admin - Super Admin only"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        fullname = data.get('fullName', '').strip()
        phone = data.get('phone', '').strip()
        is_super_admin = data.get('isSuperAdmin', False)
        is_owner = data.get('isOwner', False)

        if is_owner:
            owner = db.execute_query("SELECT id FROM admins WHERE is_owner = 1", fetch_one=True)
            if owner:
                return jsonify({'error': 'An owner account already exists'}), 409
            is_super_admin = True
        
        if not all([email, password, fullname, phone]):
            return jsonify({'error': 'All fields required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        existing = db.execute_query("SELECT id, role FROM users WHERE email = ?", (email,), fetch_one=True)
        if existing:
            # Check if this is an orphaned user (no admin record)
            admin_record = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (existing['id'],), fetch_one=True)
            if not admin_record:
                # Orphaned user - delete and allow re-registration
                db.execute_query("DELETE FROM users WHERE id = ?", (existing['id'],))
                print(f"🔄 Deleted orphaned user record for {email}")
            else:
                return jsonify({'error': 'Email already registered'}), 400
        
        password_hash = generate_password_hash(password)
        user_id = db.execute_query(
            "INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, ?, ?)",
            (email, password_hash, 'admin', True)
        )
        
        current_admin = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (session['user_id'],), fetch_one=True)
        
        db.execute_query(
            "INSERT INTO admins (user_id, full_name, phone, is_super_admin, is_owner, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, fullname, phone, 1 if is_super_admin else 0, 1 if is_owner else 0,
             current_admin['id'] if current_admin else None)
        )
        
        print(f"Admin created: {email}")
        log_activity('create_admin', 'admin', target_type='admin', target_name=fullname, details=f'Email: {email}')
        return jsonify({'message': 'Admin created successfully'}), 201
    except Exception as e:
        print(f"Error creating admin: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/admin/<int:admin_id>/reset-password', methods=['POST'])
@require_super_admin_auth
def reset_admin_password(admin_id):
    """Reset another admin's password - Super Admin only"""
    try:
        data = request.get_json()
        new_password = data.get('newPassword', '').strip()

        if not new_password or len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        admin = db.execute_query(
            'SELECT a.id, a.user_id, a.full_name FROM admins a WHERE a.id = ?',
            (admin_id,),
            fetch_one=True
        )
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404

        new_hash = generate_password_hash(new_password)
        db.execute_query(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_hash, admin['user_id'])
        )

        log_activity('reset_admin_password', 'admin', target_type='admin', target_id=admin_id,
                     target_name=admin['full_name'], details='Password reset by super admin')

        return jsonify({'message': f'Password reset successfully for {admin["full_name"]}'}), 200

    except Exception as e:
        print(f'Error resetting admin password: {e}')
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/admin/<int:admin_id>/reset-email', methods=['POST'])
@require_super_admin_auth
def reset_admin_email(admin_id):
    """Reset another admin's email - Super Admin only"""
    try:
        data = request.get_json()
        new_email = data.get('newEmail', '').strip().lower()

        if not new_email:
            return jsonify({'error': 'New email is required'}), 400

        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
            return jsonify({'error': 'Invalid email format'}), 400

        admin = db.execute_query(
            'SELECT a.id, a.user_id, a.full_name FROM admins a WHERE a.id = ?',
            (admin_id,),
            fetch_one=True
        )
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404

        # Check if email already taken
        existing = db.execute_query(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            (new_email, admin['user_id']),
            fetch_one=True
        )
        if existing:
            return jsonify({'error': 'Email is already in use by another account'}), 400

        old_email_row = db.execute_query(
            'SELECT email FROM users WHERE id = ?',
            (admin['user_id'],),
            fetch_one=True
        )
        old_email = old_email_row['email'] if old_email_row else 'unknown'

        db.execute_query(
            'UPDATE users SET email = ? WHERE id = ?',
            (new_email, admin['user_id'])
        )

        log_activity('reset_admin_email', 'admin', target_type='admin', target_id=admin_id,
                     target_name=admin['full_name'], details=f'Email changed from {old_email} to {new_email}')

        return jsonify({'message': f'Email reset successfully for {admin["full_name"]}'}), 200

    except Exception as e:
        print(f'Error resetting admin email: {e}')
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/admin/<int:admin_id>', methods=['DELETE'])
@require_super_admin_auth
def delete_admin(admin_id):
    """Delete admin - Super Admin only"""
    try:
        admin = db.execute_query("SELECT is_super_admin, is_owner, user_id, created_by_admin_id FROM admins WHERE id = ?", (admin_id,), fetch_one=True)
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404
        
        if admin['is_owner']:
            return jsonify({'error': 'Cannot delete the owner account'}), 403

        if admin['is_super_admin']:
            return jsonify({'error': 'Cannot delete super admin'}), 403
        
        if not admin['created_by_admin_id']:
            return jsonify({'error': 'Cannot delete system administrator'}), 403
        
        current_admin = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (session['user_id'],), fetch_one=True)
        if current_admin and current_admin['id'] == admin_id:
            return jsonify({'error': 'Cannot delete yourself'}), 403
        
        db.execute_query("DELETE FROM admins WHERE id = ?", (admin_id,))
        db.execute_query("DELETE FROM users WHERE id = ?", (admin['user_id'],))
        
        print(f"Admin {admin_id} deleted")
        log_activity('delete_admin', 'admin', target_type='admin', target_id=admin_id)
        return jsonify({'message': 'Admin deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting admin: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== STUDENT MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/students', methods=['GET'])
@require_admin_auth
def get_students():
    """Get all students"""
    try:
        # Use SQLite aggregation function
        agg_func = get_agg_func()
        
        students = db.execute_query(f"""
            SELECT 
                s.id,
                s.user_id,
                s.wapl_id,
                s.full_name,
                s.phone,
                s.profile_pic,
                s.resume,
                s.domain_id,
                s.registration_date,
                s.certificate_issued_date,
                s.certificate_expiry_date,
                s.assigned_hr_id,
                s.address,
                s.education_details,
                s.skills,
                s.projects,
                s.account_status,
                u.email,
                h.full_name as assigned_hr_name,
                h.company_name as hr_company,
                {agg_func} as domain_names
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN hrs h ON s.assigned_hr_id = h.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            GROUP BY s.id, u.email, h.full_name, h.company_name, u.email, 
                     s.user_id, s.wapl_id, s.full_name, s.phone, s.profile_pic, 
                     s.resume, s.domain_id, s.registration_date, s.certificate_issued_date, 
                     s.certificate_expiry_date, s.assigned_hr_id, s.address, 
                     s.education_details, s.skills, s.projects, s.account_status
            ORDER BY s.registration_date DESC
        """, fetch_all=True)
        
        return jsonify(students), 200
    except Exception as e:
        print(f"Error getting students: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>', methods=['GET'])
@require_admin_auth
def get_student_detail(student_id):
    """Get single student details"""
    try:
        # Use SQLite aggregation function
        agg_func = get_agg_func()
        
        student = db.execute_query(f"""
            SELECT 
                s.id,
                s.user_id,
                s.wapl_id,
                s.full_name,
                s.phone,
                s.profile_pic,
                s.resume,
                s.domain_id,
                s.registration_date,
                s.certificate_issued_date,
                s.certificate_expiry_date,
                s.assigned_hr_id,
                s.address,
                s.education_details,
                s.skills,
                s.projects,
                s.account_status,
                u.email,
                h.full_name as assigned_hr_name,
                h.company_name as hr_company,
                {agg_func} as domain_names
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN hrs h ON s.assigned_hr_id = h.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            WHERE s.id = ?
            GROUP BY s.id, u.email, h.full_name, h.company_name,
                     s.user_id, s.wapl_id, s.full_name, s.phone, s.profile_pic, 
                     s.resume, s.domain_id, s.registration_date, s.certificate_issued_date, 
                     s.certificate_expiry_date, s.assigned_hr_id, s.address, 
                     s.education_details, s.skills, s.projects, s.account_status
        """, (student_id,), fetch_one=True)
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        return jsonify(student), 200
    except Exception as e:
        print(f"Error getting student detail: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>', methods=['PUT'])
@require_admin_auth
def update_student(student_id):
    """Update student details"""
    try:
        data = request.get_json()
        
        # Check if student exists
        student = db.execute_query(
            "SELECT s.id, s.user_id FROM students s WHERE s.id = ?",
            (student_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Build update query dynamically
        updates = []
        params = []
        
        if 'fullName' in data and data['fullName']:
            updates.append("full_name = ?")
            params.append(sanitize_input(data['fullName'].strip()))
        
        if 'phone' in data and data['phone']:
            updates.append("phone = ?")
            params.append(sanitize_input(data['phone'].strip()))
        
        if 'address' in data:
            updates.append("address = ?")
            params.append(sanitize_input(data['address'].strip()) if data['address'] else None)
        
        if 'skills' in data:
            import json
            updates.append("skills = ?")
            params.append(json.dumps(data['skills']) if isinstance(data['skills'], list) else data['skills'])
        
        if 'education_details' in data:
            import json
            updates.append("education_details = ?")
            params.append(json.dumps(data['education_details']) if isinstance(data['education_details'], list) else data['education_details'])
        
        if 'projects' in data:
            import json
            updates.append("projects = ?")
            params.append(json.dumps(data['projects']) if isinstance(data['projects'], list) else data['projects'])
        
        if updates:
            params.append(student_id)
            query = f"UPDATE students SET {', '.join(updates)} WHERE id = ?"
            db.execute_query(query, tuple(params))
        
        # Update email if provided
        if 'email' in data and data['email']:
            new_email = data['email'].strip().lower()
            # Check if email is already used by another user
            existing = db.execute_query(
                "SELECT id FROM users WHERE email = ? AND id != ?",
                (new_email, student['user_id']),
                fetch_one=True
            )
            if existing:
                return jsonify({'error': 'Email already in use by another account'}), 400
            
            db.execute_query(
                "UPDATE users SET email = ? WHERE id = ?",
                (new_email, student['user_id'])
            )
        
        print(f"Student {student_id} updated")
        log_activity('update_student', 'student', target_type='student', target_id=student_id)
        return jsonify({'message': 'Student updated successfully'}), 200
    except Exception as e:
        print(f"Error updating student: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>/domains', methods=['GET'])
@require_admin_auth
def get_student_domains(student_id):
    """Get all domains assigned to a student"""
    try:
        domains = db.execute_query("""
            SELECT d.id, d.domain_name 
            FROM domains d
            JOIN student_domains sd ON d.id = sd.domain_id
            WHERE sd.student_id = ?
            ORDER BY d.domain_name
        """, (student_id,), fetch_all=True)
        
        return jsonify(domains), 200
    except Exception as e:
        print(f"Error getting student domains: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>/domains', methods=['POST'])
@require_admin_auth
def add_student_domains(student_id):
    """Add domain(s) to a student"""
    try:
        data = request.get_json()
        domain_ids = data.get('domainIds', [])
        
        if not domain_ids:
            return jsonify({'error': 'No domains provided'}), 400
        
        # Convert to list if single value
        if not isinstance(domain_ids, list):
            domain_ids = [domain_ids]
        
        # Check if student exists
        student = db.execute_query(
            "SELECT id FROM students WHERE id = ?",
            (student_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        added = 0
        for domain_id in domain_ids:
            # Check if domain exists
            domain = db.execute_query(
                "SELECT id FROM domains WHERE id = ?",
                (domain_id,),
                fetch_one=True
            )
            if not domain:
                continue
            
            # Check if already assigned
            existing = db.execute_query(
                "SELECT id, expires_at FROM student_domains WHERE student_id = ? AND domain_id = ?",
                (student_id, domain_id),
                fetch_one=True
            )
            renewal_base = datetime.now()
            if existing and existing.get('expires_at'):
                existing_expiry = existing['expires_at']
                if isinstance(existing_expiry, str):
                    try:
                        existing_expiry = datetime.fromisoformat(existing_expiry)
                    except Exception:
                        existing_expiry = datetime.now()
                if existing_expiry > renewal_base:
                    renewal_base = existing_expiry

            expires_at = get_subscription_expiry(renewal_base)

            if existing:
                db.execute_query(
                    "UPDATE student_domains SET expires_at = ? WHERE id = ?",
                    (expires_at, existing['id'])
                )
                added += 1
                continue
            
            # Add the domain
            db.execute_query(
                "INSERT INTO student_domains (student_id, domain_id, expires_at) VALUES (?, ?, ?)",
                (student_id, domain_id, expires_at)
            )
            added += 1
        
        # Update the primary domain_id if this is the first domain
        if added > 0:
            first_domain = db.execute_query(
                "SELECT domain_id FROM student_domains WHERE student_id = ? LIMIT 1",
                (student_id,),
                fetch_one=True
            )
            if first_domain:
                db.execute_query(
                    "UPDATE students SET domain_id = ? WHERE id = ?",
                    (first_domain['domain_id'], student_id)
                )

            get_student_subscription_state(student_id)
        
        # Send email notification about domains added
        if added > 0:
            try:
                student_info = get_student_notification_info(student_id)
                if student_info:
                    domain_name_list = []
                    for did in domain_ids:
                        d = db.execute_query('SELECT domain_name FROM domains WHERE id = ?', (did,), fetch_one=True)
                        if d:
                            domain_name_list.append(d['domain_name'])
                    send_student_domain_update_email(
                        student_info['email'], student_info['full_name'],
                        student_info['wapl_id'], ', '.join(domain_name_list) if domain_name_list else 'New domains',
                        action='added'
                    )
            except Exception as email_err:
                print(f"⚠️ Email notification failed: {email_err}")
        
        print(f"Added {added} domains to student {student_id}")
        log_activity('add_student_domains', 'student', target_type='student', target_id=student_id, details=f'{added} domain(s) added')
        return jsonify({'message': f'{added} domain(s) added successfully'}), 200
    except Exception as e:
        print(f"Error adding domains to student: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>/domain/<int:domain_id>', methods=['DELETE'])
@require_admin_auth
def remove_student_domain(student_id, domain_id):
    """Remove a domain from a student"""
    try:
        # Check if student exists
        student = db.execute_query(
            "SELECT id, domain_id FROM students WHERE id = ?",
            (student_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Check if domain is assigned to this student
        assignment = db.execute_query(
            "SELECT id FROM student_domains WHERE student_id = ? AND domain_id = ?",
            (student_id, domain_id),
            fetch_one=True
        )
        
        if not assignment:
            return jsonify({'error': 'Domain not assigned to this student'}), 404
        
        # Remove the domain
        db.execute_query(
            "DELETE FROM student_domains WHERE student_id = ? AND domain_id = ?",
            (student_id, domain_id)
        )
        
        # If this was the primary domain, update to another domain or null
        if student['domain_id'] == domain_id:
            next_domain = db.execute_query(
                "SELECT domain_id FROM student_domains WHERE student_id = ? LIMIT 1",
                (student_id,),
                fetch_one=True
            )
            new_primary = next_domain['domain_id'] if next_domain else None
            db.execute_query(
                "UPDATE students SET domain_id = ? WHERE id = ?",
                (new_primary, student_id)
            )

        get_student_subscription_state(student_id)
        
        # Send email notification about domain removed
        try:
            student_info = get_student_notification_info(student_id)
            domain_info = db.execute_query('SELECT domain_name FROM domains WHERE id = ?', (domain_id,), fetch_one=True)
            if student_info:
                send_student_domain_update_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'],
                    domain_info['domain_name'] if domain_info else 'a domain',
                    action='removed'
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        print(f"Removed domain {domain_id} from student {student_id}")
        log_activity('remove_student_domain', 'student', target_type='student', target_id=student_id, details=f'Domain ID: {domain_id}')
        return jsonify({'message': 'Domain removed successfully'}), 200
    except Exception as e:
        print(f"Error removing domain from student: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/create', methods=['POST'])
@require_admin_auth
def create_student():
    """Admin creates a student account directly - ACTIVE status"""
    try:
        # Handle both FormData and JSON
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
            email = sanitize_input(data.get('email', '').strip().lower())
            password = data.get('password', '')
            full_name = sanitize_input(data.get('fullName', '').strip())
            phone = sanitize_input(data.get('phone', '').strip())
            address = sanitize_input(data.get('address', '').strip())
            domain_ids = data.get('domainIds', [])
        else:
            # FormData from the form
            email = sanitize_input(request.form.get('email', '').strip().lower())
            password = request.form.get('password', '')
            full_name = sanitize_input(request.form.get('fullName', '').strip())
            phone = sanitize_input(request.form.get('phone', '').strip())
            address = sanitize_input(request.form.get('address', '').strip())
            # Parse domains from JSON string
            import json
            domains_str = request.form.get('domains', '[]')
            try:
                domain_ids = json.loads(domains_str)
            except:
                domain_ids = []
        
        print(f"📝 Creating student: {email}")
        print(f"📝 Domains: {domain_ids}")
        
        # Validation
        if not all([email, password, full_name, phone]):
            return jsonify({'error': 'Email, password, full name, and phone are required'}), 400
        
        if not domain_ids or len(domain_ids) == 0:
            return jsonify({'error': 'Please select at least one domain'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Check if email exists
        existing_user = db.execute_query(
            'SELECT id FROM users WHERE email = ?',
            (email,),
            fetch_one=True
        )
        
        if existing_user:
            # Check if user has a student profile
            existing_student = db.execute_query(
                'SELECT id FROM students WHERE user_id = ?',
                (existing_user['id'],),
                fetch_one=True
            )
            
            if existing_student:
                return jsonify({'error': 'Email already registered with a complete student profile'}), 400
            else:
                # User exists but no student profile - complete the registration
                print(f"⚠️ Found orphaned user, completing registration...")
                user_id = existing_user['id']
                
                # Update password in case it's different
                password_hash = generate_password_hash(password)
                db.execute_query(
                    'UPDATE users SET password_hash = ?, is_verified = ? WHERE id = ?',
                    (password_hash, True, user_id)
                )
        else:
            # Create new user account
            password_hash = generate_password_hash(password)
            insert_user_sql = 'INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, ?, ?)'
            user_id = db.execute_query(insert_user_sql, (email, password_hash, 'student', True))
            print(f"✅ User created with ID: {user_id}")
        
        # Validate domains
        for domain_id in domain_ids:
            domain = db.execute_query(
                'SELECT id FROM domains WHERE id = ? AND is_active = ?',
                (domain_id, True),
                fetch_one=True
            )
            if not domain:
                return jsonify({'error': f'Invalid or inactive domain selected'}), 400
        
        # Generate WAPL ID with domain-based code
        wapl_id = generate_wapl_id(domain_ids=domain_ids)
        print(f"✅ Generated WAPL ID: {wapl_id}")
        
        # Create student record
        try:
            # Try new schema with address
            # Try new schema with address
            insert_student_sql = '''INSERT INTO students 
                   (user_id, wapl_id, full_name, phone, address, account_status, registration_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?)'''
                   
            student_id = db.execute_query(
                insert_student_sql,
                (user_id, wapl_id, full_name, phone, address or '', 'active', datetime.now())
            )
            print(f"✅ Student profile created with ID: {student_id}")
        except Exception as schema_error:
            print(f"⚠️ New schema failed, trying old schema: {schema_error}")
            # Try old schema without address
            student_id = db.execute_query(
                '''INSERT INTO students 
                   (user_id, wapl_id, full_name, phone, account_status, registration_date)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (user_id, wapl_id, full_name, phone, 'active', datetime.now())
            )
            print(f"✅ Student profile created with ID: {student_id} (old schema)")
        
        # Assign domains
        try:
            for domain_id in domain_ids:
                db.execute_query(
                    "INSERT INTO student_domains (student_id, domain_id, expires_at) VALUES (?, ?, ?)",
                    (student_id, domain_id, get_subscription_expiry(datetime.now()))
                )
            print(f"✅ Assigned {len(domain_ids)} domains via junction table")
        except Exception as domain_error:
            print(f"⚠️ Junction table failed, using old domain_id column: {domain_error}")
            # Fallback to old schema - single domain
            db.execute_query(
                "UPDATE students SET domain_id = ? WHERE id = ?",
                (domain_ids[0], student_id)
            )
            print(f"✅ Assigned domain {domain_ids[0]} via domain_id column")
        
        print(f"✅✅ Student created successfully: {email} (WAPL ID: {wapl_id})")
        
        log_activity('create_student', 'student', target_type='student', target_id=student_id, target_name=full_name, details=f'WAPL ID: {wapl_id}, Email: {email}')
        
        return jsonify({
            'message': 'Student created successfully',
            'wapl_id': wapl_id,
            'status': 'active',
            'student_id': student_id
        }), 201
        
    except Exception as e:
        print(f"❌ Error creating student: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>/status', methods=['PUT'])
@require_admin_auth
def update_student_status(student_id):
    """Update student account status"""
    try:
        data = request.get_json()
        status = data.get('status', '').strip()
        
        valid_statuses = ['pending', 'approved', 'active', 'suspended', 'revoked', 'failed']
        if status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400
        
        # Verify student exists
        student_check = db.execute_query("SELECT id FROM students WHERE id = ?", (student_id,), fetch_one=True)
        if not student_check:
            return jsonify({'error': 'Student not found'}), 404
        
        db.execute_query("UPDATE students SET account_status = ? WHERE id = ?", (status, student_id))
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            if student_info:
                send_student_status_change_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], status
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        print(f"Student {student_id} status changed to {status}")
        return jsonify({'message': 'Student status updated'}), 200
    except Exception as e:
        print(f"Error updating student status: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>/approve', methods=['POST'])
@require_admin_auth
def approve_student(student_id):
    """Approve student (change status from pending to approved — exam eligible)"""
    try:
        # Get student details
        student = db.execute_query(
            "SELECT s.id, s.account_status, s.full_name, s.wapl_id, u.email FROM students s JOIN users u ON s.user_id = u.id WHERE s.id = ?",
            (student_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        if student['account_status'] != 'pending':
            return jsonify({'error': f'Only pending students can be approved. Current status: {student["account_status"]}'}), 400
        
        # Update student status to 'approved' (exam-eligible, not yet active)
        db.execute_query(
            "UPDATE students SET account_status = ? WHERE id = ?",
            ('approved', student_id)
        )
        
        # Send approval email notifying about exam requirement
        try:
            send_account_activation_email(
                to_email=student['email'],
                full_name=student['full_name'],
                wapl_id=student['wapl_id']
            )
            print(f"✅ Approval email sent to {student['email']}")
        except Exception as email_error:
            print(f"⚠️ Warning: Could not send approval email: {str(email_error)}")
        
        print(f"Student {student_id} approved (exam-eligible)")
        log_activity('approve_student', 'student', target_type='student', target_id=student_id, target_name=student['full_name'], details='Status: pending → approved')
        return jsonify({'message': 'Student approved — they can now take the assessment exam'}), 200
    except Exception as e:
        print(f"Error approving student: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>/suspend', methods=['POST'])
@require_admin_auth
def suspend_student(student_id):
    """Suspend student account"""
    try:
        student = db.execute_query(
            "SELECT account_status FROM students WHERE id = ?",
            (student_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        if student['account_status'] == 'suspended':
            return jsonify({'error': 'Student is already suspended'}), 400
        
        db.execute_query(
            "UPDATE students SET account_status = ? WHERE id = ?",
            ('suspended', student_id)
        )
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            if student_info:
                send_student_status_change_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], 'suspended'
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        print(f"Student {student_id} suspended")
        log_activity('suspend_student', 'student', target_type='student', target_id=student_id)
        return jsonify({'message': 'Student suspended successfully'}), 200
    except Exception as e:
        print(f"Error suspending student: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>/activate', methods=['POST'])
@require_admin_auth
def activate_student(student_id):
    """Activate student account (change from suspended or any status to active)"""
    try:
        student = db.execute_query(
            "SELECT account_status FROM students WHERE id = ?",
            (student_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        if student['account_status'] == 'active':
            return jsonify({'error': 'Student is already active'}), 400
        
        db.execute_query(
            "UPDATE students SET account_status = ? WHERE id = ?",
            ('active', student_id)
        )
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            if student_info:
                send_student_status_change_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], 'active'
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        print(f"Student {student_id} activated")
        log_activity('activate_student', 'student', target_type='student', target_id=student_id)
        return jsonify({'message': 'Student activated successfully'}), 200
    except Exception as e:
        print(f"Error activating student: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/student/<int:student_id>', methods=['DELETE'])
@require_admin_auth
def delete_student(student_id):
    """Delete student and all related records"""
    try:
        student = db.execute_query("SELECT user_id FROM students WHERE id = ?", (student_id,), fetch_one=True)
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Delete certificate audit records first (references certificates)
        cert_ids = db.execute_query(
            "SELECT id FROM certificates WHERE student_id = ?", (student_id,), fetch_all=True
        )
        for cert in cert_ids:
            db.execute_query("DELETE FROM certificate_audit WHERE certificate_id = ?", (cert['id'],))
        
        # Delete related records in dependency order
        db.execute_query("DELETE FROM certificates WHERE student_id = ?", (student_id,))
        db.execute_query("DELETE FROM student_domains WHERE student_id = ?", (student_id,))
        db.execute_query("DELETE FROM domain_cooldowns WHERE student_id = ?", (student_id,))
        db.execute_query("DELETE FROM recruitment_status WHERE student_id = ?", (student_id,))
        db.execute_query("DELETE FROM otp_verifications WHERE user_id = ?", (student['user_id'],))
        # Clean up exam and payment records
        try:
            db.execute_query("DELETE FROM exam_results WHERE student_id = ?", (student_id,))
            db.execute_query("DELETE FROM exam_registrations WHERE student_id = ?", (student_id,))
        except Exception:
            pass  # Tables may not exist
        
        # Now delete the student and user
        db.execute_query("DELETE FROM students WHERE id = ?", (student_id,))
        db.execute_query("DELETE FROM users WHERE id = ?", (student['user_id'],))
        
        print(f"Student {student_id} deleted with all related records")
        log_activity('delete_student', 'student', target_type='student', target_id=student_id)
        return jsonify({'message': 'Student deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting student: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/students/bulk-status', methods=['POST'])
@require_admin_auth
def bulk_update_student_status():
    """Bulk update status for multiple students (activate, suspend, approve)"""
    action = ''
    try:
        data = request.get_json()
        student_ids = data.get('student_ids', [])
        action = data.get('action', '').strip()

        valid_actions = {
            'activate': 'active',
            'suspend': 'suspended',
            'approve': 'approved'
        }

        if action not in valid_actions:
            return jsonify({'error': f'Invalid action. Must be one of: {", ".join(valid_actions.keys())}'}), 400

        if not student_ids or not isinstance(student_ids, list):
            return jsonify({'error': 'No student IDs provided'}), 400

        target_status = valid_actions[action]
        updated = 0
        skipped = 0
        errors = []
        email_queue = []  # Collect email info, send after responding

        for student_id in student_ids:
            try:
                student = db.execute_query(
                    "SELECT s.id, s.account_status, s.full_name, s.wapl_id, u.email "
                    "FROM students s JOIN users u ON s.user_id = u.id WHERE s.id = ?",
                    (student_id,), fetch_one=True
                )
                if not student:
                    errors.append(f'Student ID {student_id}: not found')
                    continue

                current_status = student['account_status']

                # Skip if already in target status
                if current_status == target_status:
                    skipped += 1
                    continue

                # For approve action, only pending students can be approved
                if action == 'approve' and current_status != 'pending':
                    skipped += 1
                    continue

                db.execute_query(
                    "UPDATE students SET account_status = ? WHERE id = ?",
                    (target_status, student_id)
                )

                # Queue email for background sending
                email_queue.append({
                    'student_id': student_id,
                    'email': student['email'],
                    'full_name': student['full_name'],
                    'wapl_id': student['wapl_id'],
                    'action': action,
                    'target_status': target_status
                })

                updated += 1
            except Exception as row_err:
                errors.append(f'Student ID {student_id}: {str(row_err)}')

        log_activity(f'bulk_{action}_students', 'student',
                     details=f'Bulk {action}: {updated} updated, {skipped} skipped, {len(errors)} errors')

        # Send emails in background thread so response is instant
        if email_queue:
            import threading
            def _send_bulk_emails(queue, app_context):
                with app_context:
                    for item in queue:
                        try:
                            if item['action'] == 'approve':
                                send_account_activation_email(
                                    to_email=item['email'],
                                    full_name=item['full_name'],
                                    wapl_id=item['wapl_id']
                                )
                            else:
                                send_student_status_change_email(
                                    item['email'], item['full_name'],
                                    item['wapl_id'], item['target_status']
                                )
                        except Exception as email_err:
                            print(f"⚠️ Email failed for student {item['student_id']}: {email_err}")

            from flask import current_app
            thread = threading.Thread(
                target=_send_bulk_emails,
                args=(email_queue, current_app._get_current_object().app_context())
            )
            thread.daemon = True
            thread.start()

        return jsonify({
            'message': f'Bulk {action} complete: {updated} updated, {skipped} skipped, {len(errors)} failed',
            'updated': updated,
            'skipped': skipped,
            'errors': errors[:50]
        }), 200
    except Exception as e:
        print(f"❌ Bulk status update error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/students/bulk-delete', methods=['POST'])
@require_admin_auth
def bulk_delete_students():
    """Bulk delete multiple students and all their related records"""
    try:
        data = request.get_json()
        student_ids = data.get('student_ids', [])

        if not student_ids or not isinstance(student_ids, list):
            return jsonify({'error': 'No student IDs provided'}), 400

        deleted = 0
        errors = []

        for student_id in student_ids:
            try:
                student = db.execute_query(
                    "SELECT user_id FROM students WHERE id = ?", (student_id,), fetch_one=True
                )
                if not student:
                    errors.append(f'Student ID {student_id}: not found')
                    continue

                # Delete certificate audit records first
                cert_ids = db.execute_query(
                    "SELECT id FROM certificates WHERE student_id = ?", (student_id,), fetch_all=True
                )
                for cert in cert_ids:
                    db.execute_query("DELETE FROM certificate_audit WHERE certificate_id = ?", (cert['id'],))

                # Delete related records in dependency order
                db.execute_query("DELETE FROM certificates WHERE student_id = ?", (student_id,))
                db.execute_query("DELETE FROM student_domains WHERE student_id = ?", (student_id,))
                db.execute_query("DELETE FROM domain_cooldowns WHERE student_id = ?", (student_id,))
                db.execute_query("DELETE FROM recruitment_status WHERE student_id = ?", (student_id,))
                db.execute_query("DELETE FROM otp_verifications WHERE user_id = ?", (student['user_id'],))
                try:
                    db.execute_query("DELETE FROM exam_results WHERE student_id = ?", (student_id,))
                    db.execute_query("DELETE FROM exam_registrations WHERE student_id = ?", (student_id,))
                except Exception:
                    pass  # Tables may not exist

                # Delete the student and user
                db.execute_query("DELETE FROM students WHERE id = ?", (student_id,))
                db.execute_query("DELETE FROM users WHERE id = ?", (student['user_id'],))

                deleted += 1
            except Exception as row_err:
                errors.append(f'Student ID {student_id}: {str(row_err)}')

        log_activity('bulk_delete_students', 'student',
                     details=f'Bulk deleted {deleted} students, {len(errors)} errors')

        return jsonify({
            'message': f'Bulk delete complete: {deleted} deleted, {len(errors)} failed',
            'deleted': deleted,
            'errors': errors[:50]
        }), 200
    except Exception as e:
        print(f"❌ Bulk delete error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ==================== HR MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/hrs', methods=['GET'])
@require_admin_auth
def get_hrs():
    """Get all HRs"""
    try:
        hrs = db.execute_query("""
            SELECT 
                h.*,
                u.email,
                reviewer.full_name as reviewed_by_admin_name,
                (SELECT COUNT(*) FROM students WHERE assigned_hr_id = h.id) as assigned_count
            FROM hrs h
            LEFT JOIN users u ON h.user_id = u.id
            LEFT JOIN admins reviewer ON h.reviewed_by_admin_id = reviewer.id
            ORDER BY CASE
                WHEN h.status = 'pending' THEN 0
                WHEN h.status = 'rejected' THEN 1
                ELSE 2
            END, h.created_at DESC
        """, fetch_all=True)
        
        return jsonify(hrs), 200
    except Exception as e:
        print(f"Error getting HRs: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>', methods=['GET'])
@require_admin_auth
def get_hr_detail(hr_id):
    """Get single HR details"""
    try:
        hr = db.execute_query("""
            SELECT 
                h.*,
                u.email,
                reviewer.full_name as reviewed_by_admin_name,
                (SELECT COUNT(*) FROM students WHERE assigned_hr_id = h.id) as assigned_count
            FROM hrs h
            LEFT JOIN users u ON h.user_id = u.id
            LEFT JOIN admins reviewer ON h.reviewed_by_admin_id = reviewer.id
            WHERE h.id = ?
        """, (hr_id,), fetch_one=True)
        
        if not hr:
            return jsonify({'error': 'HR not found'}), 404
        
        return jsonify(hr), 200
    except Exception as e:
        print(f"Error getting HR detail: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/create', methods=['POST'])
@require_admin_auth
def create_hr():
    """Create new HR"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        fullname = data.get('fullName', '').strip()
        companyname = data.get('companyName', '').strip()
        years_raw = str(data.get('yearsOfExperience', data.get('years_of_experience', '0'))).strip()
        phone = data.get('phone', '').strip()
        designation = data.get('designation', '').strip()
        
        if not all([email, password, fullname, companyname, phone, designation]):
            return jsonify({'error': 'All fields required'}), 400

        try:
            years_of_experience = int(years_raw or '0')
        except ValueError:
            return jsonify({'error': 'Years of experience must be a valid number'}), 400

        existing = db.execute_query("SELECT id FROM users WHERE email = ?", (email,), fetch_one=True)
        if existing:
            return jsonify({'error': 'Email already exists'}), 400
        
        password_hash = generate_password_hash(password)
        insert_user_sql = "INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, ?, ?)"
        user_id = db.execute_query(insert_user_sql, (email, password_hash, 'hr', True))
        
        current_admin = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (session['user_id'],), fetch_one=True)
        
        db.execute_query(
            """INSERT INTO hrs
               (user_id, full_name, company_name, years_of_experience, phone, designation,
                status, approved_at, reviewed_by_admin_id, created_by_admin_id)
               VALUES (?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?)""",
            (
                user_id,
                fullname,
                companyname,
                years_of_experience,
                phone,
                designation,
                datetime.now(),
                current_admin['id'] if current_admin else None,
                current_admin['id'] if current_admin else None
            )
        )
        
        print(f"HR created: {email}")
        log_activity('create_hr', 'hr', target_type='hr', target_name=fullname, details=f'Email: {email}')
        return jsonify({'message': 'HR created successfully'}), 201
    except Exception as e:
        print(f"Error creating HR: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>', methods=['DELETE'])
@require_admin_auth
def delete_hr(hr_id):
    """Delete HR"""
    try:
        hr = db.execute_query(
            "SELECT user_id, verification_proof_path, admin_verification_proof_path FROM hrs WHERE id = ?",
            (hr_id,),
            fetch_one=True
        )
        if not hr:
            return jsonify({'error': 'HR not found'}), 404
        
        # Unassign students before deleting HR
        db.execute_query("UPDATE students SET assigned_hr_id = NULL WHERE assigned_hr_id = ?", (hr_id,))
        db.execute_query("DELETE FROM recruitment_status WHERE hr_id = ?", (hr_id,))
        db.execute_query("DELETE FROM hrs WHERE id = ?", (hr_id,))
        db.execute_query("DELETE FROM users WHERE id = ?", (hr['user_id'],))

        proof_path = hr.get('verification_proof_path')
        if proof_path:
            try:
                full_path = os.path.join(os.getcwd(), proof_path)
                if os.path.exists(full_path):
                    os.remove(full_path)
            except Exception:
                pass

        admin_proof_path = hr.get('admin_verification_proof_path')
        if admin_proof_path:
            try:
                full_path = os.path.join(os.getcwd(), admin_proof_path)
                if os.path.exists(full_path):
                    os.remove(full_path)
            except Exception:
                pass
        
        print(f"HR {hr_id} deleted")
        log_activity('delete_hr', 'hr', target_type='hr', target_id=hr_id)
        return jsonify({'message': 'HR deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting HR: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>/verification-document', methods=['GET'])
@require_admin_auth
def view_hr_verification_document(hr_id):
    """View an HR's uploaded verification document."""
    try:
        hr = db.execute_query(
            'SELECT verification_proof_path, full_name FROM hrs WHERE id = ?',
            (hr_id,),
            fetch_one=True
        )
        if not hr or not hr.get('verification_proof_path'):
            return jsonify({'error': 'Verification document not found'}), 404

        proof_path = hr['verification_proof_path']
        file_path = os.path.join(os.getcwd(), proof_path)
        if not os.path.exists(file_path):
            return jsonify({'error': 'Verification document not found on server'}), 404

        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.pdf':
            mime_type = 'application/pdf'
        elif ext in ('.jpg', '.jpeg'):
            mime_type = 'image/jpeg'
        elif ext == '.png':
            mime_type = 'image/png'
        else:
            mime_type = 'application/octet-stream'

        return send_file(
            file_path,
            mimetype=mime_type,
            as_attachment=False,
            download_name=os.path.basename(file_path)
        )
    except Exception as e:
        print(f"Error viewing HR verification document: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>/admin-verification-document', methods=['GET'])
@require_admin_auth
def view_admin_hr_verification_document(hr_id):
    """View the admin-uploaded verification proof for an HR."""
    try:
        hr = db.execute_query(
            'SELECT admin_verification_proof_path, full_name FROM hrs WHERE id = ?',
            (hr_id,),
            fetch_one=True
        )
        if not hr or not hr.get('admin_verification_proof_path'):
            return jsonify({'error': 'Admin verification proof not found'}), 404

        proof_path = hr['admin_verification_proof_path']
        file_path = os.path.join(os.getcwd(), proof_path)
        if not os.path.exists(file_path):
            return jsonify({'error': 'Admin verification proof not found on server'}), 404

        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.pdf':
            mime_type = 'application/pdf'
        elif ext in ('.jpg', '.jpeg'):
            mime_type = 'image/jpeg'
        elif ext == '.png':
            mime_type = 'image/png'
        else:
            mime_type = 'application/octet-stream'

        return send_file(
            file_path,
            mimetype=mime_type,
            as_attachment=False,
            download_name=os.path.basename(file_path)
        )
    except Exception as e:
        print(f"Error viewing admin HR verification document: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>/admin-verification-proof', methods=['POST'])
@require_admin_auth
def upload_admin_hr_verification_proof(hr_id):
    """Upload an admin-side verification proof for an HR before approval."""
    try:
        hr = db.execute_query(
            'SELECT id, full_name, admin_verification_proof_path FROM hrs WHERE id = ?',
            (hr_id,),
            fetch_one=True
        )
        if not hr:
            return jsonify({'error': 'HR not found'}), 404

        file_storage = request.files.get('verification_proof') or request.files.get('admin_verification_proof')
        if not file_storage or not file_storage.filename:
            return jsonify({'error': 'Verification proof file is required'}), 400

        filename = secure_filename(file_storage.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ADMIN_HR_PROOF_ALLOWED_EXTENSIONS:
            return jsonify({'error': 'Verification proof must be PDF, JPG, or PNG'}), 400

        file_storage.stream.seek(0, os.SEEK_END)
        file_size = file_storage.stream.tell()
        file_storage.stream.seek(0)
        if file_size > ADMIN_HR_PROOF_MAX_BYTES:
            return jsonify({'error': 'Verification proof must be 5MB or smaller'}), 400

        new_path = _save_admin_hr_proof(file_storage)
        if not new_path:
            return jsonify({'error': 'Failed to store admin verification proof'}), 500

        old_path = hr.get('admin_verification_proof_path')
        if old_path and old_path != new_path:
            try:
                old_full_path = os.path.join(os.getcwd(), old_path)
                if os.path.exists(old_full_path):
                    os.remove(old_full_path)
            except Exception:
                pass

        admin = db.execute_query(
            'SELECT id FROM admins WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        db.execute_query(
            """UPDATE hrs
               SET admin_verification_proof_path = ?,
                   reviewed_by_admin_id = ?,
                   reviewed_at = ?
               WHERE id = ?""",
            (new_path, admin['id'] if admin else None, datetime.now(), hr_id)
        )

        log_activity(
            'upload_admin_hr_verification_proof',
            'admin',
            target_type='hr',
            target_id=hr_id,
            target_name=hr['full_name']
        )

        return jsonify({
            'message': 'Admin verification proof uploaded successfully',
            'proof_path': new_path
        }), 200
    except Exception as e:
        print(f"Error uploading admin HR verification proof: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>/approve', methods=['POST'])
@require_admin_auth
def approve_hr_registration(hr_id):
    """Approve a pending HR registration."""
    try:
        hr = db.execute_query(
            'SELECT id, user_id, full_name, status, admin_verification_proof_path FROM hrs WHERE id = ?',
            (hr_id,),
            fetch_one=True
        )
        if not hr:
            return jsonify({'error': 'HR not found'}), 404

        if not hr.get('admin_verification_proof_path'):
            return jsonify({'error': 'Admin verification proof is required before approval'}), 400

        admin = db.execute_query(
            'SELECT id FROM admins WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        db.execute_query(
            """UPDATE hrs
               SET status = 'approved',
                   rejection_reason = NULL,
                   approved_at = ?,
                   rejected_at = NULL,
                   reviewed_by_admin_id = ?,
                   reviewed_at = ?
               WHERE id = ?""",
            (datetime.now(), admin['id'] if admin else None, datetime.now(), hr_id)
        )

        log_activity(
            'approve_hr_registration',
            'admin',
            target_type='hr',
            target_id=hr_id,
            target_name=hr['full_name']
        )

        return jsonify({'message': 'HR account approved successfully'}), 200
    except Exception as e:
        print(f"Error approving HR registration: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>/reject', methods=['POST'])
@require_admin_auth
def reject_hr_registration(hr_id):
    """Reject an HR registration with optional reason."""
    try:
        hr = db.execute_query(
            'SELECT id, user_id, full_name FROM hrs WHERE id = ?',
            (hr_id,),
            fetch_one=True
        )
        if not hr:
            return jsonify({'error': 'HR not found'}), 404

        data = request.get_json(silent=True) or {}
        rejection_reason = sanitize_input((data.get('reason') or '').strip())
        admin = db.execute_query(
            'SELECT id FROM admins WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        db.execute_query(
            """UPDATE hrs
               SET status = 'rejected',
                   rejection_reason = ?,
                   rejected_at = ?,
                   reviewed_by_admin_id = ?,
                   reviewed_at = ?
               WHERE id = ?""",
            (rejection_reason or None, datetime.now(), admin['id'] if admin else None, datetime.now(), hr_id)
        )

        log_activity(
            'reject_hr_registration',
            'admin',
            target_type='hr',
            target_id=hr_id,
            target_name=hr['full_name'],
            details=rejection_reason if rejection_reason else None
        )

        return jsonify({'message': 'HR account rejected successfully'}), 200
    except Exception as e:
        print(f"Error rejecting HR registration: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr/<int:hr_id>/students', methods=['GET'])
@require_admin_auth
def get_hr_students(hr_id):
    """Get students assigned to specific HR"""
    try:
        agg_func = get_agg_func()
        students = db.execute_query(f"""
            SELECT 
                s.*,
                u.email,
                {agg_func} as domain_names
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            WHERE s.assigned_hr_id = ?
            GROUP BY s.id, u.email
            ORDER BY s.full_name
        """, (hr_id,), fetch_all=True)
        
        return jsonify(students), 200
    except Exception as e:
        print(f"Error getting HR students: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== STUDENT ASSIGNMENT ROUTES ====================


@admin_bp.route('/api/admin/assign-students', methods=['POST'])
@require_admin_auth
def assign_students():
    """Assign students to HR"""
    try:
        data = request.get_json()
        hr_id = data.get('hrId')
        student_ids = data.get('studentIds', [])
        
        if not hr_id or not student_ids:
            return jsonify({'error': 'HR ID and student IDs required'}), 400
        
        hr = db.execute_query("SELECT id FROM hrs WHERE id = ?", (hr_id,), fetch_one=True)
        if not hr:
            return jsonify({'error': 'HR not found'}), 404
        
        for student_id in student_ids:
            db.execute_query("UPDATE students SET assigned_hr_id = ? WHERE id = ?", (hr_id, student_id))
        
        # Send email notifications to assigned students
        try:
            hr_details = db.execute_query(
                'SELECT full_name, company_name FROM hrs WHERE id = ?',
                (hr_id,), fetch_one=True
            )
            if hr_details:
                for student_id in student_ids:
                    try:
                        student_info = get_student_notification_info(student_id)
                        if student_info:
                            send_student_hr_assigned_email(
                                student_info['email'], student_info['full_name'],
                                student_info['wapl_id'], hr_details['full_name'],
                                hr_details['company_name']
                            )
                    except Exception:
                        pass
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        print(f"{len(student_ids)} students assigned to HR {hr_id}")
        log_activity('assign_students', 'assignment', target_type='hr', target_id=hr_id, details=f'{len(student_ids)} students assigned')
        return jsonify({'message': f'{len(student_ids)} students assigned successfully'}), 200
    except Exception as e:
        print(f"Error assigning students: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/unassign-students', methods=['POST'])
@require_admin_auth
def unassign_students():
    """Unassign students from HR"""
    try:
        data = request.get_json()
        student_ids = data.get('studentIds', [])
        
        if not student_ids:
            return jsonify({'error': 'Student IDs required'}), 400
        
        for student_id in student_ids:
            db.execute_query("UPDATE students SET assigned_hr_id = NULL WHERE id = ?", (student_id,))
        
        # Send email notifications to unassigned students
        try:
            for student_id in student_ids:
                try:
                    student_info = get_student_notification_info(student_id)
                    if student_info:
                        send_student_hr_unassigned_email(
                            student_info['email'], student_info['full_name'],
                            student_info['wapl_id']
                        )
                except Exception:
                    pass
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        print(f"{len(student_ids)} students unassigned")
        log_activity('unassign_students', 'assignment', target_type='student', details=f'{len(student_ids)} students unassigned')
        return jsonify({'message': f'{len(student_ids)} students unassigned successfully'}), 200
    except Exception as e:
        print(f"Error unassigning students: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/students/unassigned', methods=['GET'])
@require_admin_auth
def get_unassigned_students():
    """Get students not assigned to any HR"""
    try:
        agg_func = get_agg_func()
        students = db.execute_query(f"""
            SELECT 
                s.*,
                u.email,
                {agg_func} as domain_names
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            WHERE s.assigned_hr_id IS NULL AND s.account_status = 'active'
            GROUP BY s.id, u.email
            ORDER BY s.full_name
        """, fetch_all=True)
        
        return jsonify(students), 200
    except Exception as e:
        print(f"Error getting unassigned students: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== DOMAIN MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/domains', methods=['GET'])
def get_domains():
    """Get all domains - PUBLIC ACCESS for registration"""
    try:
        is_active_val = get_bool_literal(True)
        domains = db.execute_query(f"SELECT id, domain_name, short_code, price, is_active FROM domains WHERE is_active = {is_active_val} ORDER BY domain_name", fetch_all=True)
        return jsonify(domains), 200
    except Exception as e:
        print(f"Error getting domains: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/domain/create', methods=['POST'])
@require_super_admin_auth
def create_domain():
    """Create new domain - Super Admin only"""
    try:
        data = request.get_json()
        domain_name = data.get('domainName', '').strip()
        short_code = data.get('shortCode', '').strip().upper()
        price = data.get('price', 166)  # Default price
        
        if not domain_name:
            return jsonify({'error': 'Domain name required'}), 400
        
        if not short_code:
            # Auto-generate short code
            from database import generate_short_code
            short_code = generate_short_code(domain_name)
        
        try:
            price = int(price)
            if price < 0:
                price = 0
        except (ValueError, TypeError):
            price = 166
        
        existing = db.execute_query(
            "SELECT id FROM domains WHERE LOWER(domain_name) = LOWER(?)",
            (domain_name,),
            fetch_one=True
        )
        if existing:
            return jsonify({'error': 'Domain already exists'}), 400
        
        # Check short_code uniqueness
        existing_code = db.execute_query(
            "SELECT id FROM domains WHERE UPPER(short_code) = UPPER(?)",
            (short_code,),
            fetch_one=True
        )
        if existing_code:
            return jsonify({'error': f'Short code "{short_code}" is already in use'}), 400
        
        current_admin = db.execute_query("SELECT id FROM admins WHERE user_id = ?", (session['user_id'],), fetch_one=True)
        
        db.execute_query(
            "INSERT INTO domains (domain_name, short_code, is_active, price, created_by_admin_id) VALUES (?, ?, ?, ?, ?)",
            (domain_name, short_code, True, price, current_admin['id'] if current_admin else None)
        )
        
        print(f"Domain '{domain_name}' ({short_code}) created with price ₹{price}")
        log_activity('create_domain', 'domain', target_type='domain', target_name=domain_name, details=f'Code: {short_code}, Price: ₹{price}')
        return jsonify({'message': 'Domain created successfully'}), 201
    except Exception as e:
        print(f"Error creating domain: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/domain/<int:domain_id>/short-code', methods=['PUT'])
@require_super_admin_auth
def update_domain_short_code(domain_id):
    """Update domain short code - Super Admin only"""
    try:
        data = request.get_json()
        short_code = data.get('shortCode', '').strip().upper()
        
        if not short_code:
            return jsonify({'error': 'Short code is required'}), 400
        
        domain = db.execute_query("SELECT * FROM domains WHERE id = ?", (domain_id,), fetch_one=True)
        if not domain:
            return jsonify({'error': 'Domain not found'}), 404
        
        # Check uniqueness
        existing = db.execute_query(
            "SELECT id FROM domains WHERE UPPER(short_code) = UPPER(?) AND id != ?",
            (short_code, domain_id),
            fetch_one=True
        )
        if existing:
            return jsonify({'error': f'Short code "{short_code}" is already in use'}), 400
        
        db.execute_query("UPDATE domains SET short_code = ? WHERE id = ?", (short_code, domain_id))
        
        print(f"Domain {domain_id} short code updated to '{short_code}'")
        return jsonify({'message': f'Short code updated to "{short_code}"'}), 200
    except Exception as e:
        print(f"Error updating short code: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/domain/<int:domain_id>/status', methods=['PUT'])
@require_super_admin_auth
def update_domain_status(domain_id):
    """Toggle domain active status - Super Admin only"""
    try:
        data = request.get_json()
        is_active = data.get('isActive', False)
        
        domain = db.execute_query("SELECT * FROM domains WHERE id = ?", (domain_id,), fetch_one=True)
        if not domain:
            return jsonify({'error': 'Domain not found'}), 404
        
        db.execute_query("UPDATE domains SET is_active = ? WHERE id = ?", (get_bool_value(is_active), domain_id))
        
        action = 'activated' if is_active else 'deactivated'
        print(f"Domain {domain_id} {action}")
        log_activity('toggle_domain_status', 'domain', target_type='domain', target_id=domain_id, details=f'Domain {action}')
        return jsonify({'message': f'Domain {action} successfully'}), 200
    except Exception as e:
        print(f"Error updating domain status: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/domain/<int:domain_id>/price', methods=['PUT'])
@require_super_admin_auth
def update_domain_price(domain_id):
    """Update domain price - Super Admin only"""
    try:
        data = request.get_json()
        price = data.get('price', 0)
        
        try:
            price = int(price)
            if price < 0:
                price = 0
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid price value'}), 400
        
        domain = db.execute_query("SELECT * FROM domains WHERE id = ?", (domain_id,), fetch_one=True)
        if not domain:
            return jsonify({'error': 'Domain not found'}), 404
        
        db.execute_query("UPDATE domains SET price = ? WHERE id = ?", (price, domain_id))
        
        print(f"Domain {domain_id} price updated to ₹{price}")
        log_activity('update_domain_price', 'domain', target_type='domain', target_id=domain_id, details=f'Price: ₹{price}')
        return jsonify({'message': f'Price updated to ₹{price}'}), 200
    except Exception as e:
        print(f"Error updating domain price: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/domain/<int:domain_id>', methods=['DELETE'])
@require_super_admin_auth
def delete_domain(domain_id):
    """Delete domain - Super Admin only"""
    try:
        domain = db.execute_query("SELECT domain_name FROM domains WHERE id = ?", (domain_id,), fetch_one=True)
        if not domain:
            return jsonify({'error': 'Domain not found'}), 404
        
        students_count = db.execute_query(
            "SELECT COUNT(*) as count FROM student_domains WHERE domain_id = ?",
            (domain_id,),
            fetch_one=True
        )
        
        if students_count and students_count['count'] > 0:
            return jsonify({'error': f'Cannot delete domain. {students_count["count"]} student(s) are assigned'}), 400
        
        db.execute_query("DELETE FROM domains WHERE id = ?", (domain_id,))
        
        print(f"Domain '{domain['domain_name']}' deleted")
        log_activity('delete_domain', 'domain', target_type='domain', target_id=domain_id, target_name=domain['domain_name'])
        return jsonify({'message': f'Domain deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting domain: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== CERTIFICATE MANAGEMENT ROUTES ====================


@admin_bp.route('/api/admin/students/without-certificates', methods=['GET'])
@require_admin_auth
def get_students_without_certificates():
    """Get all active students without certificates"""
    try:
        is_active_val = get_bool_literal(True)
        passed_val = get_bool_literal(True)
        
        students = db.execute_query(f"""
            SELECT 
                s.id, s.user_id, s.wapl_id, s.full_name, s.phone, s.address,
                s.account_status, s.registration_date, s.profile_pic, s.resume,
                u.email
            FROM students s
            JOIN users u ON s.user_id = u.id
            LEFT JOIN certificates c ON s.id = c.student_id AND c.is_active = {is_active_val}
            WHERE s.account_status = 'active' AND c.id IS NULL
            GROUP BY s.id, s.user_id, s.wapl_id, s.full_name, s.phone, s.address,
                     s.account_status, s.registration_date, s.profile_pic, s.resume, u.email
            ORDER BY s.registration_date DESC
        """, fetch_all=True)
        
        # For each student, get only PASSED domain names
        for student in students:
            passed_domains = db.execute_query(f"""
                SELECT DISTINCT d.domain_name
                FROM exam_results er
                JOIN domains d ON er.domain_id = d.id
                WHERE er.student_id = ? AND er.passed = {passed_val}
                ORDER BY d.domain_name
            """, (student['id'],), fetch_all=True)
            
            if passed_domains:
                student['domain_names'] = ', '.join([pd['domain_name'] for pd in passed_domains])
            else:
                # Fallback: show all enrolled domains
                all_domains = db.execute_query("""
                    SELECT d.domain_name FROM student_domains sd
                    JOIN domains d ON sd.domain_id = d.id
                    WHERE sd.student_id = ?
                    ORDER BY d.domain_name
                """, (student['id'],), fetch_all=True)
                student['domain_names'] = ', '.join([d['domain_name'] for d in all_domains]) if all_domains else 'N/A'
        
        return jsonify({'students': students}), 200
    except Exception as e:
        print(f"Error getting students without certificates: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/certificates', methods=['GET'])
@require_admin_auth
def get_certificates():
    """Get all active certificates"""
    try:
        is_active_val = get_bool_literal(True)
        passed_val = get_bool_literal(True)
        certificates = db.execute_query(f"""
            SELECT 
                c.*,
                s.full_name as student_name,
                s.wapl_id
            FROM certificates c
            LEFT JOIN students s ON c.student_id = s.id
            WHERE c.is_active = {is_active_val}
            ORDER BY c.issue_date DESC
        """, fetch_all=True)
        
        # For each certificate, get only passed domain names
        for cert in certificates:
            sid = cert.get('student_id')
            if sid:
                passed_domains = db.execute_query(f"""
                    SELECT DISTINCT d.domain_name
                    FROM exam_results er
                    JOIN domains d ON er.domain_id = d.id
                    WHERE er.student_id = ? AND er.passed = {passed_val}
                    ORDER BY d.domain_name
                """, (sid,), fetch_all=True)
                
                if passed_domains:
                    cert['domain_names'] = ', '.join([pd['domain_name'] for pd in passed_domains])
                else:
                    all_domains = db.execute_query("""
                        SELECT d.domain_name FROM student_domains sd
                        JOIN domains d ON sd.domain_id = d.id
                        WHERE sd.student_id = ?
                        ORDER BY d.domain_name
                    """, (sid,), fetch_all=True)
                    cert['domain_names'] = ', '.join([d['domain_name'] for d in all_domains]) if all_domains else 'N/A'
            else:
                cert['domain_names'] = 'N/A'
        
        return jsonify(certificates), 200
    except Exception as e:
        print(f"Error getting certificates: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/certificates/issue', methods=['POST'])
@require_admin_auth
def issue_certificates():
    """Issue certificates to students with QR code and PDF generation"""
    try:
        from utils import generate_certificate_id, generate_qr_code, generate_certificate_pdf
        
        data = request.get_json()
        student_ids = data.get('studentIds', [])
        
        if not student_ids:
            return jsonify({'error': 'Student IDs required'}), 400
        
        # Create directories if they don't exist
        os.makedirs('uploads/certificates', exist_ok=True)
        os.makedirs('uploads/qr_codes', exist_ok=True)
        
        issued_count = 0
        errors = []
        agg_func = get_agg_func()
        is_active_val = get_bool_literal(True)
        
        for student_id in student_ids:
            try:
                # Get student details
                student = db.execute_query("""
                    SELECT s.*, u.email
                    FROM students s
                    LEFT JOIN users u ON s.user_id = u.id
                    WHERE s.id = ?
                """, (student_id,), fetch_one=True)
                
                if not student:
                    errors.append(f"Student ID {student_id} not found")
                    continue
                
                # Get only PASSED domain names from exam results
                passed_val = get_bool_literal(True)
                passed_domains = db.execute_query(f"""
                    SELECT DISTINCT d.domain_name
                    FROM exam_results er
                    JOIN domains d ON er.domain_id = d.id
                    WHERE er.student_id = ? AND er.passed = {passed_val}
                    ORDER BY d.domain_name
                """, (student_id,), fetch_all=True)
                
                if passed_domains:
                    student['domain_names'] = ', '.join([pd['domain_name'] for pd in passed_domains])
                else:
                    # Fallback: use all enrolled domains if no exam results exist
                    all_domains = db.execute_query("""
                        SELECT d.domain_name FROM student_domains sd
                        JOIN domains d ON sd.domain_id = d.id
                        WHERE sd.student_id = ?
                        ORDER BY d.domain_name
                    """, (student_id,), fetch_all=True)
                    student['domain_names'] = ', '.join([d['domain_name'] for d in all_domains]) if all_domains else None
                
                # Check if already has active certificate
                existing_cert = db.execute_query(
                    f"SELECT id FROM certificates WHERE student_id = ? AND is_active = {is_active_val}",
                    (student_id,),
                    fetch_one=True
                )
                
                if existing_cert:
                    errors.append(f"{student['full_name']} already has an active certificate")
                    continue
                
                # Generate unique certificate ID
                cert_unique_id = generate_certificate_id()
                
                # Set dates
                issue_date = datetime.now()
                expiry_date = issue_date + timedelta(days=365)
                
                # Format dates for display
                issue_date_str = issue_date.strftime('%d %B %Y')
                expiry_date_str = expiry_date.strftime('%d %B %Y')
                
                # Generate QR code - links to report download
                # Use environment variable for domain, fallback to request host
                base_domain = os.environ.get('APP_DOMAIN', request.host_url.rstrip('/'))
                qr_data = f"{base_domain}/download-report/{cert_unique_id}"
                qr_code_path = f'uploads/qr_codes/{cert_unique_id}_qr.png'
                generate_qr_code(qr_data, qr_code_path)
                
                # Generate PDF certificate using your template
                pdf_path = f'uploads/certificates/{cert_unique_id}.pdf'
                
                domain_display = student['domain_names'] if student['domain_names'] else 'General Training'
                
                generate_certificate_pdf(
                    student_name=student['full_name'],
                    wapl_id=student['wapl_id'],
                    domain_name=domain_display,
                    issue_date=issue_date_str,
                    expiry_date=expiry_date_str,
                    qr_code_path=qr_code_path,
                    output_path=pdf_path,
                    hr_name=None,
                    certificate_text=f"This certificate recognizes the candidate's hands-on experience in {domain_display} and successful assessment by WAPL."
                )
                
                # Insert certificate into database
                is_active_val = get_bool_literal(True)
                db.execute_query(f"""
                    INSERT INTO certificates 
                    (student_id, certificate_unique_id, issue_date, expiry_date, 
                     qr_code, pdf_path, is_active, display_name) 
                    VALUES (?, ?, ?, ?, ?, ?, {is_active_val}, ?)
                """, (
                    student_id,
                    cert_unique_id,
                    issue_date,
                    expiry_date,
                    qr_code_path,
                    pdf_path,
                    student['full_name']
                ))
                
                # Update student record
                db.execute_query("""
                    UPDATE students 
                    SET certificate_issued_date = ?, certificate_expiry_date = ? 
                    WHERE id = ?
                """, (issue_date, expiry_date, student_id))
                
                issued_count += 1
                print(f"✅ Certificate {cert_unique_id} issued to {student['full_name']}")
                
                # Send email notification
                try:
                    if student.get('email'):
                        send_student_certificate_email(
                            student['email'], student['full_name'],
                            student['wapl_id'], cert_unique_id, action='issued'
                        )
                except Exception as email_err:
                    print(f"⚠️ Email notification failed for {student['full_name']}: {email_err}")
                
            except Exception as student_error:
                error_msg = f"Error for {student.get('full_name', f'student {student_id}') if 'student' in locals() else f'student {student_id}'}: {str(student_error)}"
                errors.append(error_msg)
                print(f"❌ {error_msg}")
        
        # Prepare response message
        if issued_count == 0 and errors:
            return jsonify({'error': '; '.join(errors)}), 400
        
        message = f'{issued_count} certificate(s) issued successfully'
        if errors:
            message += f'. Warnings: {"; ".join(errors)}'
        
        log_activity('issue_certificates', 'certificate', details=f'{issued_count} certificate(s) issued')
        
        return jsonify({
            'message': message, 
            'issued_count': issued_count,
            'errors': errors if errors else None
        }), 201
        
    except Exception as e:
        print(f"❌ Error issuing certificates: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/certificate/regenerate/<int:student_id>', methods=['POST'])
@require_admin_auth
def regenerate_certificate(student_id):
    """Regenerate certificate for a student"""
    try:
        from utils import generate_certificate_id, generate_qr_code, generate_certificate_pdf
        
        # Deactivate old certificate
        is_active_val = get_bool_literal(True)
        is_inactive_val = get_bool_literal(False)
        db.execute_query(
            f"UPDATE certificates SET is_active = {is_inactive_val} WHERE student_id = ? AND is_active = {is_active_val}",
            (student_id,)
        )
        
        # Get student details
        student = db.execute_query("""
            SELECT s.*, u.email
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            WHERE s.id = ?
        """, (student_id,), fetch_one=True)
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Get only PASSED domain names from exam results
        passed_val = get_bool_literal(True)
        passed_domains = db.execute_query(f"""
            SELECT DISTINCT d.domain_name
            FROM exam_results er
            JOIN domains d ON er.domain_id = d.id
            WHERE er.student_id = ? AND er.passed = {passed_val}
            ORDER BY d.domain_name
        """, (student_id,), fetch_all=True)
        
        if passed_domains:
            domain_display = ', '.join([pd['domain_name'] for pd in passed_domains])
        else:
            # Fallback: use all enrolled domains if no exam results
            agg_func = get_agg_func()
            fallback = db.execute_query(f"""
                SELECT {agg_func} as domain_names
                FROM student_domains sd
                JOIN domains d ON sd.domain_id = d.id
                WHERE sd.student_id = ?
            """, (student_id,), fetch_one=True)
            domain_display = fallback['domain_names'] if fallback and fallback['domain_names'] else 'General Training'
        
        # Create directories
        os.makedirs('uploads/certificates', exist_ok=True)
        os.makedirs('uploads/qr_codes', exist_ok=True)
        
        # Generate new certificate
        cert_unique_id = generate_certificate_id()
        issue_date = datetime.now()
        expiry_date = issue_date + timedelta(days=365)
        issue_date_str = issue_date.strftime('%d %B %Y')
        expiry_date_str = expiry_date.strftime('%d %B %Y')
        
        # Generate QR code and PDF - links to report download
        base_domain = os.environ.get('APP_DOMAIN', request.host_url.rstrip('/'))
        qr_data = f"{base_domain}/download-report/{cert_unique_id}"
        qr_code_path = f'uploads/qr_codes/{cert_unique_id}_qr.png'
        generate_qr_code(qr_data, qr_code_path)
        
        pdf_path = f'uploads/certificates/{cert_unique_id}.pdf'
        
        generate_certificate_pdf(
            student_name=student['full_name'],
            wapl_id=student['wapl_id'],
            domain_name=domain_display,
            issue_date=issue_date_str,
            expiry_date=expiry_date_str,
            qr_code_path=qr_code_path,
            output_path=pdf_path,
            hr_name=None,
            certificate_text=f"This certificate recognizes the candidate's hands-on experience in {domain_display} and successful assessment by WAPL."
        )
        
        # Insert new certificate
        is_active_new = get_bool_literal(True)
        db.execute_query(f"""
            INSERT INTO certificates 
            (student_id, certificate_unique_id, issue_date, expiry_date, 
             qr_code, pdf_path, is_active, display_name) 
            VALUES (?, ?, ?, ?, ?, ?, {is_active_new}, ?)
        """, (
            student_id,
            cert_unique_id,
            issue_date,
            expiry_date,
            qr_code_path,
            pdf_path,
            student['full_name']
        ))
        
        # Update student record
        db.execute_query("""
            UPDATE students 
            SET certificate_issued_date = ?, certificate_expiry_date = ? 
            WHERE id = ?
        """, (issue_date, expiry_date, student_id))
        
        print(f"✅ Certificate {cert_unique_id} regenerated for {student['full_name']}")
        
        log_activity('regenerate_certificate', 'certificate', target_type='student', target_id=student_id, target_name=student['full_name'], details=f'Cert: {cert_unique_id}')
        
        # Send email notification
        try:
            if student.get('email'):
                send_student_certificate_email(
                    student['email'], student['full_name'],
                    student['wapl_id'], cert_unique_id, action='regenerated'
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        return jsonify({
            'message': 'Certificate regenerated successfully',
            'certificate_id': cert_unique_id
        }), 200
        
    except Exception as e:
        print(f"❌ Error regenerating certificate: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/download/certificate/<string:cert_id>', methods=['GET'])
@require_admin_auth
def download_certificate_admin(cert_id):
    """Download certificate PDF - Admin access"""
    try:
        is_active_val = get_bool_literal(True)
        cert = db.execute_query(
            f"SELECT * FROM certificates WHERE certificate_unique_id = ? AND is_active = {is_active_val}",
            (cert_id,),
            fetch_one=True
        )
        
        if not cert:
            return jsonify({'error': 'Certificate not found'}), 404
        
        pdf_path = cert['pdf_path']
        if not os.path.exists(pdf_path):
            return jsonify({'error': 'Certificate file not found'}), 404
        
        return send_file(pdf_path, as_attachment=True, download_name=f"{cert_id}.pdf")
        
    except Exception as e:
        print(f"❌ Error downloading certificate: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/certificate/<string:cert_id>/upload-report', methods=['POST'])
@require_admin_auth
def upload_report_file(cert_id):
    """Upload a report file for a certificate (accessed via QR code scan)"""
    try:
        from werkzeug.utils import secure_filename
        from storage import Storage
        
        # Verify certificate exists
        is_active_val = get_bool_literal(True)
        cert = db.execute_query(
            f"SELECT * FROM certificates WHERE certificate_unique_id = ? AND is_active = {is_active_val}",
            (cert_id,),
            fetch_one=True
        )
        
        if not cert:
            return jsonify({'error': 'Certificate not found'}), 404
        
        # Check if file was uploaded
        if 'report_file' not in request.files:
            return jsonify({'error': 'No report file provided'}), 400
        
        file = request.files['report_file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type (allow PDF, DOC, DOCX, images)
        allowed_extensions = {'pdf', 'doc', 'docx', 'png', 'jpg', 'jpeg'}
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'}), 400
        
        # Create reports directory
        os.makedirs('uploads/reports', exist_ok=True)
        
        # Save file with certificate ID prefix
        new_filename = f'{cert_id}_report.{file_ext}'
        report_path = f'uploads/reports/{new_filename}'
        
        # Save locally or to cloud storage
        try:
            saved_path = Storage.save_file(file, subfolder='reports')
            if saved_path:
                # Storage returns path without 'uploads/' prefix, add it for consistency
                if saved_path.startswith('http'):
                    report_path = saved_path  # GCS URL
                elif not saved_path.startswith('uploads/'):
                    report_path = f'uploads/{saved_path}'
                else:
                    report_path = saved_path
            else:
                # Fallback to local save
                file.save(report_path)
        except Exception as storage_error:
            print(f"Storage error, saving locally: {storage_error}")
            # Reset file position in case storage tried to read it
            file.seek(0)
            file.save(report_path)
        
        # Update certificate with report file path
        db.execute_query(
            "UPDATE certificates SET report_file = ? WHERE certificate_unique_id = ?",
            (report_path, cert_id)
        )
        
        print(f"✅ Report file uploaded for certificate {cert_id}: {report_path}")
        
        log_activity('upload_report', 'certificate', target_type='certificate', target_name=cert_id, details=f'File: {report_path}')
        
        return jsonify({
            'message': 'Report file uploaded successfully',
            'report_path': report_path
        }), 200
        
    except Exception as e:
        print(f"❌ Error uploading report file: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/certificate/<string:cert_id>/report', methods=['DELETE'])
@require_admin_auth
def delete_report_file(cert_id):
    """Delete the report file for a certificate"""
    try:
        # Get certificate
        cert = db.execute_query(
            "SELECT * FROM certificates WHERE certificate_unique_id = ?",
            (cert_id,),
            fetch_one=True
        )
        
        if not cert:
            return jsonify({'error': 'Certificate not found'}), 404
        
        report_file = cert.get('report_file')
        
        if report_file:
            # Try to delete the file
            if not report_file.startswith('http'):
                file_path = os.path.join(os.getcwd(), report_file)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"✅ Deleted report file: {file_path}")
        
        # Clear report_file from database
        db.execute_query(
            "UPDATE certificates SET report_file = NULL WHERE certificate_unique_id = ?",
            (cert_id,)
        )
        
        log_activity('delete_report', 'certificate', target_type='certificate', target_name=cert_id)
        
        return jsonify({'message': 'Report file deleted successfully'}), 200
        
    except Exception as e:
        print(f"❌ Error deleting report file: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/certificate/<int:cert_id>', methods=['DELETE'])
@require_admin_auth
def delete_certificate(cert_id):
    """Delete/deactivate a certificate"""
    try:
        # Get certificate details
        cert = db.execute_query(
            "SELECT * FROM certificates WHERE id = ?",
            (cert_id,),
            fetch_one=True
        )
        
        if not cert:
            return jsonify({'error': 'Certificate not found'}), 404
        
        # Deactivate certificate
        is_inactive_val = get_bool_literal(False)
        db.execute_query(
            f"UPDATE certificates SET is_active = {is_inactive_val} WHERE id = ?",
            (cert_id,)
        )
        
        # Log audit trail
        db.execute_query("""
            INSERT INTO certificate_audit (certificate_id, action, reason, changed_by_admin_id)
            VALUES (?, 'deactivate', 'Deleted by admin', ?)
        """, (cert_id, session.get('user_id')))
        
        print(f"✅ Certificate {cert['certificate_unique_id']} deactivated")
        
        log_activity('delete_certificate', 'certificate', target_type='certificate', target_name=cert['certificate_unique_id'])
        
        return jsonify({'message': 'Certificate deleted successfully'}), 200
        
    except Exception as e:
        print(f"❌ Error deleting certificate: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ==================== RECRUITMENT ROUTES ====================


@admin_bp.route('/api/admin/recruitment', methods=['GET'])
@require_admin_auth
def get_recruitment_stats():
    """Get recruitment statistics"""
    try:
        agg_fn = get_agg_func()
        records = db.execute_query(f"""
            SELECT 
                r.*,
                s.full_name as student_name,
                s.wapl_id,
                h.full_name as hr_name,
                h.company_name,
                (SELECT {agg_fn} FROM student_domains sd 
                 LEFT JOIN domains d ON sd.domain_id = d.id 
                 WHERE sd.student_id = s.id) as domain_name
            FROM recruitment_status r
            LEFT JOIN students s ON r.student_id = s.id
            LEFT JOIN hrs h ON r.hr_id = h.id
            ORDER BY r.updated_at DESC
        """, fetch_all=True)
        
        return jsonify(records), 200
    except Exception as e:
        print(f"Error getting recruitment stats: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/admin/recruitment/summary', methods=['GET'])
@require_admin_auth
def get_recruitment_summary():
    """Get overall recruitment summary"""
    try:
        total_assignments = db.execute_query(
            'SELECT COUNT(DISTINCT student_id) as count FROM recruitment_status',
            fetch_one=True
        )

        viewed = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE status = 'viewed'",
            fetch_one=True
        )
        
        shortlisted = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE status = 'shortlisted'",
            fetch_one=True
        )
        
        interviews = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE status = 'interview_scheduled'",
            fetch_one=True
        )
        
        selected = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE status = 'selected'",
            fetch_one=True
        )
        
        rejected = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE status = 'rejected'",
            fetch_one=True
        )

        # "Viewed" also includes assigned students who have no recruitment_status record yet
        # (HR viewed them but didn't take any explicit action)
        assigned_without_status = db.execute_query(
            '''SELECT COUNT(DISTINCT s.id) as count FROM students s 
               WHERE s.assigned_hr_id IS NOT NULL 
               AND s.id NOT IN (SELECT DISTINCT student_id FROM recruitment_status)''',
            fetch_one=True
        )
        total_viewed = (viewed['count'] if viewed else 0) + (assigned_without_status['count'] if assigned_without_status else 0)
        total_in_pipeline = (total_assignments['count'] if total_assignments else 0) + (assigned_without_status['count'] if assigned_without_status else 0)
        
        # Get breakdown by HR
        by_hr = db.execute_query("""
            SELECT 
                h.id,
                h.full_name,
                h.company_name,
                COUNT(r.id) as total_actions,
                SUM(CASE WHEN r.status = 'shortlisted' THEN 1 ELSE 0 END) as shortlisted_count,
                SUM(CASE WHEN r.status = 'interview_scheduled' THEN 1 ELSE 0 END) as interview_count,
                SUM(CASE WHEN r.status = 'selected' THEN 1 ELSE 0 END) as selected_count,
                SUM(CASE WHEN r.status = 'rejected' THEN 1 ELSE 0 END) as rejected_count
            FROM hrs h
            LEFT JOIN recruitment_status r ON h.id = r.hr_id
            GROUP BY h.id
            ORDER BY total_actions DESC
        """, fetch_all=True)
        
        return jsonify({
            'total_students_in_pipeline': total_in_pipeline,
            'viewed': total_viewed,
            'shortlisted': shortlisted['count'] if shortlisted else 0,
            'interviews_scheduled': interviews['count'] if interviews else 0,
            'selected': selected['count'] if selected else 0,
            'rejected': rejected['count'] if rejected else 0,
            'by_hr': by_hr
        }), 200
    except Exception as e:
        print(f"Error getting recruitment summary: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/recruitment/filter', methods=['GET'])
@require_admin_auth
def filter_recruitment():
    """Filter recruitment records"""
    try:
        status_filter = request.args.get('status', '')
        hr_filter = request.args.get('hr_id', '')
        
        agg_fn = get_agg_func()
        query = f"""
            SELECT 
                r.*,
                s.full_name as student_name,
                s.wapl_id,
                u_s.email as email,
                h.full_name as hr_name,
                h.company_name,
                (SELECT {agg_fn} FROM student_domains sd 
                 LEFT JOIN domains d ON sd.domain_id = d.id 
                 WHERE sd.student_id = s.id) as domain_name
            FROM recruitment_status r
            LEFT JOIN students s ON r.student_id = s.id
            LEFT JOIN users u_s ON s.user_id = u_s.id
            LEFT JOIN hrs h ON r.hr_id = h.id
            WHERE 1=1
        """
        
        params = []
        
        if status_filter:
            query += " AND r.status = ?"
            params.append(status_filter)
        
        if hr_filter:
            query += " AND r.hr_id = ?"
            params.append(int(hr_filter))
        
        query += " ORDER BY r.updated_at DESC"
        
        records = db.execute_query(query, tuple(params), fetch_all=True)
        return jsonify(records), 200
    except Exception as e:
        print(f"Error filtering recruitment: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/recruitment/student/<int:student_id>', methods=['GET'])
@require_admin_auth
def get_student_recruitment_history(student_id):
    """Get recruitment history for a student across all HRs"""
    try:
        history = db.execute_query("""
            SELECT 
                r.*,
                h.full_name as hr_name,
                h.company_name
            FROM recruitment_status r
            LEFT JOIN hrs h ON r.hr_id = h.id
            WHERE r.student_id = ?
            ORDER BY r.updated_at DESC
        """, (student_id,), fetch_all=True)
        
        return jsonify(history), 200
    except Exception as e:
        print(f"Error getting student recruitment history: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== HR PROFILE APPROVAL ROUTES ====================


@admin_bp.route('/api/admin/hr-profile-changes', methods=['GET'])
@require_admin_auth
def get_hr_profile_changes():
    """Get all HR profile change requests"""
    try:
        changes = db.execute_query("""
            SELECT pc.*, h.full_name as hr_name, h.company_name, u.email as hr_email
            FROM hr_profile_changes pc
            JOIN hrs h ON pc.hr_id = h.id
            JOIN users u ON pc.user_id = u.id
            ORDER BY CASE WHEN pc.status = 'pending' THEN 0 ELSE 1 END, pc.created_at DESC
        """, fetch_all=True)
        
        result = []
        for change in changes:
            c = dict(change)
            c['changes'] = json.loads(c['changes'])
            result.append(c)
        
        return jsonify(result), 200
    except Exception as e:
        print(f"Error getting HR profile changes: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr-profile-changes/<int:change_id>/approve', methods=['POST'])
@require_admin_auth
def approve_hr_profile_change(change_id):
    """Approve an HR profile change request"""
    try:
        # Get the change request
        change = db.execute_query(
            "SELECT * FROM hr_profile_changes WHERE id = ? AND status = 'pending'",
            (change_id,),
            fetch_one=True
        )
        
        if not change:
            return jsonify({'error': 'Change request not found or already processed'}), 404
        
        changes = json.loads(change['changes'])
        hr_id = change['hr_id']
        user_id = change['user_id']
        
        # Apply the changes to hrs table
        hr_fields = ['full_name', 'phone', 'designation', 'company_name', 'company_website', 'address']
        for field in hr_fields:
            if field in changes:
                db.execute_query(
                    f'UPDATE hrs SET {field} = ? WHERE id = ?',
                    (changes[field], hr_id)
                )
        
        # Apply email change to users table
        if 'email' in changes:
            existing = db.execute_query(
                'SELECT id FROM users WHERE email = ? AND id != ?',
                (changes['email'], user_id),
                fetch_one=True
            )
            if existing:
                return jsonify({'error': 'Email is already in use by another account'}), 400
            
            db.execute_query(
                'UPDATE users SET email = ? WHERE id = ?',
                (changes['email'], user_id)
            )
        
        # Get admin ID
        admin = db.execute_query(
            'SELECT id FROM admins WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )
        
        data = request.get_json() or {}
        review_notes = sanitize_input(data.get('notes', '')).strip()
        
        db.execute_query(
            """UPDATE hr_profile_changes 
               SET status = 'approved', reviewed_by_admin_id = ?, review_notes = ?, reviewed_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (admin['id'] if admin else None, review_notes, change_id)
        )
        
        log_activity('approve_hr_profile_change', 'hr', target_type='hr_profile_change', target_id=change_id, details=f'Notes: {review_notes}' if review_notes else None)
        
        return jsonify({'message': 'Profile changes approved and applied successfully'}), 200
    except Exception as e:
        print(f"Error approving HR profile change: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/hr-profile-changes/<int:change_id>/reject', methods=['POST'])
@require_admin_auth
def reject_hr_profile_change(change_id):
    """Reject an HR profile change request"""
    try:
        change = db.execute_query(
            "SELECT * FROM hr_profile_changes WHERE id = ? AND status = 'pending'",
            (change_id,),
            fetch_one=True
        )
        
        if not change:
            return jsonify({'error': 'Change request not found or already processed'}), 404
        
        admin = db.execute_query(
            'SELECT id FROM admins WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )
        
        data = request.get_json() or {}
        review_notes = sanitize_input(data.get('notes', '')).strip()
        
        db.execute_query(
            """UPDATE hr_profile_changes 
               SET status = 'rejected', reviewed_by_admin_id = ?, review_notes = ?, reviewed_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (admin['id'] if admin else None, review_notes, change_id)
        )
        
        log_activity('reject_hr_profile_change', 'hr', target_type='hr_profile_change', target_id=change_id, details=f'Notes: {review_notes}' if review_notes else None)
        
        return jsonify({'message': 'Profile change request rejected'}), 200
    except Exception as e:
        print(f"Error rejecting HR profile change: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== REPORTS & EXPORT ROUTES ====================


def _build_csv_response(rows, headers, filename_prefix):
    """Helper to build a CSV file response with timestamped filename"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    filename = f"{filename_prefix}_{timestamp}.csv"
    
    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )
    return response


def _build_xlsx_response(rows, headers, filename_prefix):
    """Helper to build a styled XLSX file response with timestamped filename"""
    wb = Workbook()
    ws = wb.active
    ws.title = filename_prefix.replace('_export', '').replace('_', ' ').title()
    
    # Styles
    header_font = Font(bold=True, color='FFFFFF', size=11)
    header_fill = PatternFill(start_color='4472C4', end_color='4472C4', fill_type='solid')
    header_alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
    thin_border = Border(
        left=Side(style='thin', color='D9D9D9'),
        right=Side(style='thin', color='D9D9D9'),
        top=Side(style='thin', color='D9D9D9'),
        bottom=Side(style='thin', color='D9D9D9')
    )
    alt_fill = PatternFill(start_color='F2F7FB', end_color='F2F7FB', fill_type='solid')
    
    # Write headers
    for col_idx, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = thin_border
    
    # Write data rows
    for row_idx, row_data in enumerate(rows, 2):
        for col_idx, value in enumerate(row_data, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin_border
            cell.alignment = Alignment(vertical='center', wrap_text=True)
            if row_idx % 2 == 0:
                cell.fill = alt_fill
    
    # Auto-fit column widths
    for col_idx, header in enumerate(headers, 1):
        max_len = len(str(header))
        for row_data in rows:
            if col_idx - 1 < len(row_data):
                max_len = max(max_len, len(str(row_data[col_idx - 1] or '')))
        ws.column_dimensions[ws.cell(row=1, column=col_idx).column_letter].width = min(max_len + 4, 50)
    
    # Freeze header row
    ws.freeze_panes = 'A2'
    
    # Auto-filter
    ws.auto_filter.ref = ws.dimensions
    
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    filename = f"{filename_prefix}_{timestamp}.xlsx"
    
    response = Response(
        output.getvalue(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )
    return response


def _build_export_response(rows, headers, filename_prefix, fmt='csv'):
    """Build export response in requested format (csv or xlsx)"""
    if fmt == 'xlsx':
        return _build_xlsx_response(rows, headers, filename_prefix)
    return _build_csv_response(rows, headers, filename_prefix)


def _style_worksheet(ws, headers, rows):
    """Apply consistent styling to a worksheet (reusable for single and multi-sheet)"""
    header_font = Font(bold=True, color='FFFFFF', size=11)
    header_fill = PatternFill(start_color='4472C4', end_color='4472C4', fill_type='solid')
    header_alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
    thin_border = Border(
        left=Side(style='thin', color='D9D9D9'),
        right=Side(style='thin', color='D9D9D9'),
        top=Side(style='thin', color='D9D9D9'),
        bottom=Side(style='thin', color='D9D9D9')
    )
    alt_fill = PatternFill(start_color='F2F7FB', end_color='F2F7FB', fill_type='solid')
    
    for col_idx, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = thin_border
    
    for row_idx, row_data in enumerate(rows, 2):
        for col_idx, value in enumerate(row_data, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin_border
            cell.alignment = Alignment(vertical='center', wrap_text=True)
            if row_idx % 2 == 0:
                cell.fill = alt_fill
    
    for col_idx, header in enumerate(headers, 1):
        max_len = len(str(header))
        for row_data in rows:
            if col_idx - 1 < len(row_data):
                max_len = max(max_len, len(str(row_data[col_idx - 1] or '')))
        ws.column_dimensions[ws.cell(row=1, column=col_idx).column_letter].width = min(max_len + 4, 50)
    
    ws.freeze_panes = 'A2'
    ws.auto_filter.ref = ws.dimensions


def _build_multi_sheet_xlsx(sheets_data, filename_prefix):
    """Build a single XLSX workbook with multiple sheets.
    sheets_data: list of (sheet_name, headers, rows) tuples"""
    wb = Workbook()
    # Remove default sheet
    wb.remove(wb.active)
    
    for sheet_name, headers, rows in sheets_data:
        ws = wb.create_sheet(title=sheet_name)
        _style_worksheet(ws, headers, rows)
    
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    filename = f"{filename_prefix}_{timestamp}.xlsx"
    
    return Response(
        output.getvalue(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


# ---- Data-fetching helpers (used by individual exports and bulk) ----


def _fetch_students_data(date_from='', date_to=''):
    agg = get_agg_func()
    where_clauses = []
    params = []
    if date_from:
        where_clauses.append("s.registration_date >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("s.registration_date <= ?")
        params.append(date_to + ' 23:59:59')
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    students = db.execute_query(f"""
        SELECT s.id, s.wapl_id, s.full_name, s.phone, s.account_status,
            s.address, s.education_details, s.skills, s.projects,
            s.registration_date, s.certificate_issued_date, u.email,
            h.full_name as hr_name, h.company_name as hr_company,
            {agg} as domains
        FROM students s
        LEFT JOIN users u ON s.user_id = u.id
        LEFT JOIN hrs h ON s.assigned_hr_id = h.id
        LEFT JOIN student_domains sd ON s.id = sd.student_id
        LEFT JOIN domains d ON sd.domain_id = d.id
        {where_sql}
        GROUP BY s.id, s.wapl_id, s.full_name, s.phone, s.account_status,
                 s.address, s.education_details, s.skills, s.projects,
                 s.registration_date, s.certificate_issued_date,
                 u.email, h.full_name, h.company_name
        ORDER BY s.registration_date DESC
    """, tuple(params), fetch_all=True)
    headers = ['WAPL ID', 'Full Name', 'Email', 'Phone', 'Status', 'Domains',
               'Address', 'Education', 'Skills', 'Projects',
               'Assigned HR', 'HR Company', 'Registration Date', 'Certificate Issued']
    rows = []
    for s in students:
        rows.append([
            s.get('wapl_id', ''), s.get('full_name', ''), s.get('email', ''),
            s.get('phone', ''), s.get('account_status', ''),
            s.get('domains', ''), s.get('address', ''),
            s.get('education_details', ''), s.get('skills', ''),
            s.get('projects', ''),
            s.get('hr_name', ''), s.get('hr_company', ''),
            str(s.get('registration_date', '')),
            str(s.get('certificate_issued_date', '') or '')
        ])
    return headers, rows


def _fetch_payments_data(date_from='', date_to=''):
    where_clauses = []
    params = []
    if date_from:
        where_clauses.append("p.created_at >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("p.created_at <= ?")
        params.append(date_to + ' 23:59:59')
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    payments = db.execute_query(f"""
        SELECT p.razorpay_order_id, p.razorpay_payment_id, p.email,
            p.amount, p.currency, p.domain_count, p.status,
            p.created_at, p.verified_at,
            s.wapl_id, s.full_name as student_name, s.phone as student_phone
        FROM payments p
        LEFT JOIN users u ON p.email = u.email
        LEFT JOIN students s ON u.id = s.user_id
        {where_sql}
        ORDER BY p.created_at DESC
    """, tuple(params), fetch_all=True)
    headers = ['Order ID', 'Payment ID', 'Email', 'Student Name', 'WAPL ID',
               'Phone', 'Amount (Paise)', 'Amount (₹)', 'Currency',
               'Domain Count', 'Status', 'Created At', 'Verified At']
    rows = []
    for p in payments:
        amount_paise = p.get('amount', 0)
        amount_rupees = round(amount_paise / 100, 2) if amount_paise else 0
        rows.append([
            p.get('razorpay_order_id', ''), p.get('razorpay_payment_id', ''),
            p.get('email', ''), p.get('student_name', ''), p.get('wapl_id', ''),
            p.get('student_phone', ''),
            amount_paise, amount_rupees, p.get('currency', 'INR'),
            p.get('domain_count', ''), p.get('status', ''),
            str(p.get('created_at', '')), str(p.get('verified_at', '') or '')
        ])
    return headers, rows


def _fetch_domains_data():
    domains = db.execute_query("""
        SELECT d.id, d.domain_name, d.short_code, d.price, d.is_active, d.created_at,
            COUNT(sd.student_id) as student_count
        FROM domains d
        LEFT JOIN student_domains sd ON d.id = sd.domain_id
        GROUP BY d.id, d.domain_name, d.short_code, d.price, d.is_active, d.created_at
        ORDER BY d.domain_name
    """, fetch_all=True)
    headers = ['Domain ID', 'Domain Name', 'Short Code', 'Price (₹)',
               'Active', 'Student Count', 'Est. Revenue (₹)', 'Created At']
    rows = []
    for d in domains:
        price = d.get('price', 0) or 0
        student_count = d.get('student_count', 0) or 0
        rows.append([
            d.get('id', ''), d.get('domain_name', ''), d.get('short_code', ''),
            price, 'Yes' if d.get('is_active') else 'No',
            student_count, price * student_count,
            str(d.get('created_at', ''))
        ])
    return headers, rows


def _fetch_recruitment_data(date_from='', date_to=''):
    where_clauses = []
    params = []
    if date_from:
        where_clauses.append("rs.created_at >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("rs.created_at <= ?")
        params.append(date_to + ' 23:59:59')
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    records = db.execute_query(f"""
        SELECT rs.status, rs.notes, rs.created_at, rs.updated_at,
            s.wapl_id, s.full_name as student_name, s.phone as student_phone,
            u_s.email as student_email,
            h.full_name as hr_name, h.company_name as hr_company,
            u_h.email as hr_email
        FROM recruitment_status rs
        LEFT JOIN students s ON rs.student_id = s.id
        LEFT JOIN users u_s ON s.user_id = u_s.id
        LEFT JOIN hrs h ON rs.hr_id = h.id
        LEFT JOIN users u_h ON h.user_id = u_h.id
        {where_sql}
        ORDER BY rs.updated_at DESC
    """, tuple(params), fetch_all=True)
    headers = ['Student Name', 'WAPL ID', 'Student Email', 'Student Phone',
               'HR Name', 'HR Company', 'HR Email', 'Status', 'Notes',
               'Created At', 'Last Updated']
    rows = []
    for r in records:
        rows.append([
            r.get('student_name', ''), r.get('wapl_id', ''),
            r.get('student_email', ''), r.get('student_phone', ''),
            r.get('hr_name', ''), r.get('hr_company', ''),
            r.get('hr_email', ''),
            r.get('status', ''), r.get('notes', ''),
            str(r.get('created_at', '')), str(r.get('updated_at', ''))
        ])
    return headers, rows


def _fetch_certificates_data(date_from='', date_to=''):
    where_clauses = []
    params = []
    if date_from:
        where_clauses.append("c.issue_date >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("c.issue_date <= ?")
        params.append(date_to + ' 23:59:59')
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    certs = db.execute_query(f"""
        SELECT c.certificate_unique_id, c.issue_date, c.expiry_date,
            c.is_active, c.display_name, c.report_file,
            s.wapl_id, s.full_name as student_name,
            u.email as student_email,
            h.full_name as issued_by_hr
        FROM certificates c
        LEFT JOIN students s ON c.student_id = s.id
        LEFT JOIN users u ON s.user_id = u.id
        LEFT JOIN hrs h ON c.issued_by_hr_id = h.id
        {where_sql}
        ORDER BY c.issue_date DESC
    """, tuple(params), fetch_all=True)
    headers = ['Certificate ID', 'Display Name', 'Student Name', 'WAPL ID',
               'Student Email', 'Issued By HR', 'Active',
               'Issue Date', 'Expiry Date', 'Has Report']
    rows = []
    for c in certs:
        rows.append([
            c.get('certificate_unique_id', ''), c.get('display_name', ''),
            c.get('student_name', ''), c.get('wapl_id', ''),
            c.get('student_email', ''), c.get('issued_by_hr', ''),
            'Yes' if c.get('is_active') else 'No',
            str(c.get('issue_date', '')), str(c.get('expiry_date', '')),
            'Yes' if c.get('report_file') else 'No'
        ])
    return headers, rows


def _fetch_hr_approvals_data(date_from='', date_to=''):
    where_clauses = []
    params = []
    if date_from:
        where_clauses.append("hpc.created_at >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("hpc.created_at <= ?")
        params.append(date_to + ' 23:59:59')
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    changes = db.execute_query(f"""
        SELECT hpc.id, hpc.changes, hpc.status, hpc.review_notes,
            hpc.created_at, hpc.reviewed_at,
            h.full_name as hr_name, h.company_name,
            u.email as hr_email,
            a.full_name as reviewed_by
        FROM hr_profile_changes hpc
        LEFT JOIN hrs h ON hpc.hr_id = h.id
        LEFT JOIN users u ON hpc.user_id = u.id
        LEFT JOIN admins a ON hpc.reviewed_by_admin_id = a.id
        {where_sql}
        ORDER BY hpc.created_at DESC
    """, tuple(params), fetch_all=True)
    headers = ['Request ID', 'HR Name', 'Company', 'HR Email', 'Changes',
               'Status', 'Review Notes', 'Reviewed By', 'Submitted At', 'Reviewed At']
    rows = []
    for c in changes:
        rows.append([
            c.get('id', ''), c.get('hr_name', ''), c.get('company_name', ''),
            c.get('hr_email', ''), c.get('changes', ''),
            c.get('status', ''), c.get('review_notes', ''),
            c.get('reviewed_by', ''),
            str(c.get('created_at', '')), str(c.get('reviewed_at', '') or '')
        ])
    return headers, rows


@admin_bp.route('/api/admin/export/counts', methods=['GET'])
@require_admin_auth
def get_export_counts():
    """Get record counts for each exportable category, with optional date range"""
    try:
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')
        
        date_clause_students = ""
        date_clause_payments = ""
        date_clause_recruitment = ""
        date_clause_certificates = ""
        date_clause_hr_changes = ""
        params_students = []
        params_payments = []
        params_recruitment = []
        params_certificates = []
        params_hr_changes = []
        
        if date_from:
            date_clause_students += " AND s.registration_date >= ?"
            params_students.append(date_from)
            date_clause_payments += " AND p.created_at >= ?"
            params_payments.append(date_from)
            date_clause_recruitment += " AND rs.created_at >= ?"
            params_recruitment.append(date_from)
            date_clause_certificates += " AND c.issue_date >= ?"
            params_certificates.append(date_from)
            date_clause_hr_changes += " AND hpc.created_at >= ?"
            params_hr_changes.append(date_from)
        if date_to:
            date_clause_students += " AND s.registration_date <= ?"
            params_students.append(date_to + ' 23:59:59')
            date_clause_payments += " AND p.created_at <= ?"
            params_payments.append(date_to + ' 23:59:59')
            date_clause_recruitment += " AND rs.created_at <= ?"
            params_recruitment.append(date_to + ' 23:59:59')
            date_clause_certificates += " AND c.issue_date <= ?"
            params_certificates.append(date_to + ' 23:59:59')
            date_clause_hr_changes += " AND hpc.created_at <= ?"
            params_hr_changes.append(date_to + ' 23:59:59')
        
        students_count = db.execute_query(
            f"SELECT COUNT(*) as count FROM students s WHERE 1=1{date_clause_students}",
            tuple(params_students), fetch_one=True
        )
        payments_count = db.execute_query(
            f"SELECT COUNT(*) as count FROM payments p WHERE 1=1{date_clause_payments}",
            tuple(params_payments), fetch_one=True
        )
        domains_count = db.execute_query(
            "SELECT COUNT(*) as count FROM domains", fetch_one=True
        )
        recruitment_count = db.execute_query(
            f"SELECT COUNT(*) as count FROM recruitment_status rs WHERE 1=1{date_clause_recruitment}",
            tuple(params_recruitment), fetch_one=True
        )
        certificates_count = db.execute_query(
            f"SELECT COUNT(*) as count FROM certificates c WHERE 1=1{date_clause_certificates}",
            tuple(params_certificates), fetch_one=True
        )
        hr_changes_count = db.execute_query(
            f"SELECT COUNT(*) as count FROM hr_profile_changes hpc WHERE 1=1{date_clause_hr_changes}",
            tuple(params_hr_changes), fetch_one=True
        )
        
        return jsonify({
            'students': students_count['count'] if students_count else 0,
            'payments': payments_count['count'] if payments_count else 0,
            'domains': domains_count['count'] if domains_count else 0,
            'recruitment': recruitment_count['count'] if recruitment_count else 0,
            'certificates': certificates_count['count'] if certificates_count else 0,
            'hr_changes': hr_changes_count['count'] if hr_changes_count else 0,
        }), 200
    except Exception as e:
        print(f"Error getting export counts: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/export/students', methods=['GET'])
@require_admin_auth
def export_students():
    """Export students data as CSV"""
    try:
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')
        status_filter = request.args.get('status', '')
        
        agg = get_agg_func()
        where_clauses = []
        params = []
        
        if date_from:
            where_clauses.append("s.registration_date >= ?")
            params.append(date_from)
        if date_to:
            where_clauses.append("s.registration_date <= ?")
            params.append(date_to + ' 23:59:59')
        if status_filter:
            where_clauses.append("s.account_status = ?")
            params.append(status_filter)
        
        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        
        students = db.execute_query(f"""
            SELECT 
                s.id, s.wapl_id, s.full_name, s.phone, s.account_status,
                s.address, s.education_details, s.skills, s.projects,
                s.registration_date, s.certificate_issued_date,
                u.email,
                h.full_name as hr_name, h.company_name as hr_company,
                {agg} as domains
            FROM students s
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN hrs h ON s.assigned_hr_id = h.id
            LEFT JOIN student_domains sd ON s.id = sd.student_id
            LEFT JOIN domains d ON sd.domain_id = d.id
            {where_sql}
            GROUP BY s.id, s.wapl_id, s.full_name, s.phone, s.account_status,
                     s.address, s.education_details, s.skills, s.projects,
                     s.registration_date, s.certificate_issued_date,
                     u.email, h.full_name, h.company_name
            ORDER BY s.registration_date DESC
        """, tuple(params), fetch_all=True)
        
        headers = ['WAPL ID', 'Full Name', 'Email', 'Phone', 'Status', 'Domains',
                    'Address', 'Education', 'Skills', 'Projects',
                    'Assigned HR', 'HR Company', 'Registration Date', 'Certificate Issued']
        
        rows = []
        for s in students:
            rows.append([
                s.get('wapl_id', ''), s.get('full_name', ''), s.get('email', ''),
                s.get('phone', ''), s.get('account_status', ''),
                s.get('domains', ''), s.get('address', ''),
                s.get('education_details', ''), s.get('skills', ''),
                s.get('projects', ''),
                s.get('hr_name', ''), s.get('hr_company', ''),
                str(s.get('registration_date', '')),
                str(s.get('certificate_issued_date', '') or '')
            ])
        
        fmt = request.args.get('format', 'csv')
        log_activity('export_students', 'export', details=f'Format: {fmt}')
        return _build_export_response(rows, headers, 'students_export', fmt)
    except Exception as e:
        print(f"Error exporting students: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/export/payments', methods=['GET'])
@require_admin_auth
def export_payments():
    """Export payments data as CSV"""
    try:
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')
        status_filter = request.args.get('status', '')
        
        where_clauses = []
        params = []
        
        if date_from:
            where_clauses.append("p.created_at >= ?")
            params.append(date_from)
        if date_to:
            where_clauses.append("p.created_at <= ?")
            params.append(date_to + ' 23:59:59')
        if status_filter:
            where_clauses.append("p.status = ?")
            params.append(status_filter)
        
        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        
        payments = db.execute_query(f"""
            SELECT 
                p.razorpay_order_id, p.razorpay_payment_id, p.email,
                p.amount, p.currency, p.domain_count, p.status,
                p.created_at, p.verified_at,
                s.wapl_id, s.full_name as student_name, s.phone as student_phone
            FROM payments p
            LEFT JOIN users u ON p.email = u.email
            LEFT JOIN students s ON u.id = s.user_id
            {where_sql}
            ORDER BY p.created_at DESC
        """, tuple(params), fetch_all=True)
        
        headers = ['Order ID', 'Payment ID', 'Email', 'Student Name', 'WAPL ID',
                    'Phone', 'Amount (Paise)', 'Amount (₹)', 'Currency', 
                    'Domain Count', 'Status', 'Created At', 'Verified At']
        
        rows = []
        for p in payments:
            amount_paise = p.get('amount', 0)
            amount_rupees = round(amount_paise / 100, 2) if amount_paise else 0
            rows.append([
                p.get('razorpay_order_id', ''), p.get('razorpay_payment_id', ''),
                p.get('email', ''), p.get('student_name', ''), p.get('wapl_id', ''),
                p.get('student_phone', ''),
                amount_paise, amount_rupees, p.get('currency', 'INR'),
                p.get('domain_count', ''), p.get('status', ''),
                str(p.get('created_at', '')), str(p.get('verified_at', '') or '')
            ])
        
        fmt = request.args.get('format', 'csv')
        log_activity('export_payments', 'export', details=f'Format: {fmt}')
        return _build_export_response(rows, headers, 'payments_export', fmt)
    except Exception as e:
        print(f"Error exporting payments: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/export/domains', methods=['GET'])
@require_admin_auth
def export_domains():
    """Export domains data as CSV with student counts and revenue"""
    try:
        is_active_val = get_bool_literal(True)
        
        domains = db.execute_query(f"""
            SELECT 
                d.id, d.domain_name, d.short_code, d.price, d.is_active, d.created_at,
                COUNT(sd.student_id) as student_count
            FROM domains d
            LEFT JOIN student_domains sd ON d.id = sd.domain_id
            GROUP BY d.id, d.domain_name, d.short_code, d.price, d.is_active, d.created_at
            ORDER BY d.domain_name
        """, fetch_all=True)
        
        headers = ['Domain ID', 'Domain Name', 'Short Code', 'Price (₹)', 
                    'Active', 'Student Count', 'Est. Revenue (₹)', 'Created At']
        
        rows = []
        for d in domains:
            price = d.get('price', 0) or 0
            student_count = d.get('student_count', 0) or 0
            rows.append([
                d.get('id', ''), d.get('domain_name', ''), d.get('short_code', ''),
                price, 'Yes' if d.get('is_active') else 'No',
                student_count, price * student_count,
                str(d.get('created_at', ''))
            ])
        
        fmt = request.args.get('format', 'csv')
        log_activity('export_domains', 'export', details=f'Format: {fmt}')
        return _build_export_response(rows, headers, 'domains_export', fmt)
    except Exception as e:
        print(f"Error exporting domains: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/export/recruitment', methods=['GET'])
@require_admin_auth
def export_recruitment():
    """Export recruitment status data as CSV"""
    try:
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')
        status_filter = request.args.get('status', '')
        
        where_clauses = []
        params = []
        
        if date_from:
            where_clauses.append("rs.created_at >= ?")
            params.append(date_from)
        if date_to:
            where_clauses.append("rs.created_at <= ?")
            params.append(date_to + ' 23:59:59')
        if status_filter:
            where_clauses.append("rs.status = ?")
            params.append(status_filter)
        
        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        
        records = db.execute_query(f"""
            SELECT 
                rs.status, rs.notes, rs.created_at, rs.updated_at,
                s.wapl_id, s.full_name as student_name, s.phone as student_phone,
                u_s.email as student_email,
                h.full_name as hr_name, h.company_name as hr_company,
                u_h.email as hr_email
            FROM recruitment_status rs
            LEFT JOIN students s ON rs.student_id = s.id
            LEFT JOIN users u_s ON s.user_id = u_s.id
            LEFT JOIN hrs h ON rs.hr_id = h.id
            LEFT JOIN users u_h ON h.user_id = u_h.id
            {where_sql}
            ORDER BY rs.updated_at DESC
        """, tuple(params), fetch_all=True)
        
        headers = ['Student Name', 'WAPL ID', 'Student Email', 'Student Phone',
                    'HR Name', 'HR Company', 'HR Email', 'Status', 'Notes',
                    'Created At', 'Last Updated']
        
        rows = []
        for r in records:
            rows.append([
                r.get('student_name', ''), r.get('wapl_id', ''),
                r.get('student_email', ''), r.get('student_phone', ''),
                r.get('hr_name', ''), r.get('hr_company', ''),
                r.get('hr_email', ''),
                r.get('status', ''), r.get('notes', ''),
                str(r.get('created_at', '')), str(r.get('updated_at', ''))
            ])
        
        fmt = request.args.get('format', 'csv')
        log_activity('export_recruitment', 'export', details=f'Format: {fmt}')
        return _build_export_response(rows, headers, 'recruitment_export', fmt)
    except Exception as e:
        print(f"Error exporting recruitment: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/export/certificates', methods=['GET'])
@require_admin_auth
def export_certificates():
    """Export certificates data as CSV"""
    try:
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')
        
        where_clauses = []
        params = []
        
        if date_from:
            where_clauses.append("c.issue_date >= ?")
            params.append(date_from)
        if date_to:
            where_clauses.append("c.issue_date <= ?")
            params.append(date_to + ' 23:59:59')
        
        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        
        certs = db.execute_query(f"""
            SELECT 
                c.certificate_unique_id, c.issue_date, c.expiry_date,
                c.is_active, c.display_name, c.report_file,
                s.wapl_id, s.full_name as student_name,
                u.email as student_email,
                h.full_name as issued_by_hr
            FROM certificates c
            LEFT JOIN students s ON c.student_id = s.id
            LEFT JOIN users u ON s.user_id = u.id
            LEFT JOIN hrs h ON c.issued_by_hr_id = h.id
            {where_sql}
            ORDER BY c.issue_date DESC
        """, tuple(params), fetch_all=True)
        
        headers = ['Certificate ID', 'Display Name', 'Student Name', 'WAPL ID', 
                    'Student Email', 'Issued By HR', 'Active',
                    'Issue Date', 'Expiry Date', 'Has Report']
        
        rows = []
        for c in certs:
            rows.append([
                c.get('certificate_unique_id', ''), c.get('display_name', ''),
                c.get('student_name', ''), c.get('wapl_id', ''),
                c.get('student_email', ''), c.get('issued_by_hr', ''),
                'Yes' if c.get('is_active') else 'No',
                str(c.get('issue_date', '')), str(c.get('expiry_date', '')),
                'Yes' if c.get('report_file') else 'No'
            ])
        
        fmt = request.args.get('format', 'csv')
        log_activity('export_certificates', 'export', details=f'Format: {fmt}')
        return _build_export_response(rows, headers, 'certificates_export', fmt)
    except Exception as e:
        print(f"Error exporting certificates: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/export/hr-approvals', methods=['GET'])
@require_admin_auth
def export_hr_approvals():
    """Export HR profile change requests as CSV"""
    try:
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')
        status_filter = request.args.get('status', '')
        
        where_clauses = []
        params = []
        
        if date_from:
            where_clauses.append("hpc.created_at >= ?")
            params.append(date_from)
        if date_to:
            where_clauses.append("hpc.created_at <= ?")
            params.append(date_to + ' 23:59:59')
        if status_filter:
            where_clauses.append("hpc.status = ?")
            params.append(status_filter)
        
        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        
        changes = db.execute_query(f"""
            SELECT 
                hpc.id, hpc.changes, hpc.status, hpc.review_notes,
                hpc.created_at, hpc.reviewed_at,
                h.full_name as hr_name, h.company_name,
                u.email as hr_email,
                a.full_name as reviewed_by
            FROM hr_profile_changes hpc
            LEFT JOIN hrs h ON hpc.hr_id = h.id
            LEFT JOIN users u ON hpc.user_id = u.id
            LEFT JOIN admins a ON hpc.reviewed_by_admin_id = a.id
            {where_sql}
            ORDER BY hpc.created_at DESC
        """, tuple(params), fetch_all=True)
        
        headers = ['Request ID', 'HR Name', 'Company', 'HR Email', 'Changes',
                    'Status', 'Review Notes', 'Reviewed By', 'Submitted At', 'Reviewed At']
        
        rows = []
        for c in changes:
            rows.append([
                c.get('id', ''), c.get('hr_name', ''), c.get('company_name', ''),
                c.get('hr_email', ''), c.get('changes', ''),
                c.get('status', ''), c.get('review_notes', ''),
                c.get('reviewed_by', ''),
                str(c.get('created_at', '')), str(c.get('reviewed_at', '') or '')
            ])
        
        fmt = request.args.get('format', 'csv')
        log_activity('export_hr_approvals', 'export', details=f'Format: {fmt}')
        return _build_export_response(rows, headers, 'hr_approvals_export', fmt)
    except Exception as e:
        print(f"Error exporting HR approvals: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/export/all', methods=['GET'])
@require_admin_auth
def export_all_workbook():
    """Export all data as a single XLSX workbook with multiple sheets"""
    try:
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')

        sheets = []

        h, r = _fetch_students_data(date_from, date_to)
        sheets.append(('Students', h, r))

        h, r = _fetch_payments_data(date_from, date_to)
        sheets.append(('Payments', h, r))

        h, r = _fetch_domains_data()
        sheets.append(('Domains', h, r))

        h, r = _fetch_recruitment_data(date_from, date_to)
        sheets.append(('Recruitment', h, r))

        h, r = _fetch_certificates_data(date_from, date_to)
        sheets.append(('Certificates', h, r))

        h, r = _fetch_hr_approvals_data(date_from, date_to)
        sheets.append(('HR Approvals', h, r))

        log_activity('export_all', 'export', details='Full XLSX workbook')
        return _build_multi_sheet_xlsx(sheets, 'wapl_complete_report')
    except Exception as e:
        print(f"Error exporting all data: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== EXAM MANAGEMENT ROUTES (OFFLINE) ====================


@admin_bp.route('/secure-admin-panel/wapl/exams')
@require_admin_auth
def admin_exams_page():
    """Admin exam management page"""
    return render_template('admin/exams.html')


@admin_bp.route('/api/admin/exams/overview', methods=['GET'])
@require_admin_auth
def get_exams_overview():
    """Get exam overview: domains, configs, schedules, registrations, results"""
    try:
        is_active_val = get_bool_literal(True)

        # Get all active domains
        domains = db.execute_query(
            f'SELECT id, domain_name FROM domains WHERE is_active = {is_active_val} ORDER BY domain_name',
            fetch_all=True
        )

        overview = []
        for domain in domains:
            # Exam config
            config = db.execute_query(
                'SELECT * FROM exam_config WHERE domain_id = ?',
                (domain['id'],),
                fetch_one=True
            )

            # Upcoming schedules
            today = datetime.now().strftime('%Y-%m-%d')
            schedules = db.execute_query(
                f'''SELECT es.*,
                       (SELECT COUNT(*) FROM exam_registrations WHERE schedule_id = es.id) as registered_count
                   FROM exam_schedules es
                   WHERE es.domain_id = ? AND es.is_active = {is_active_val}
                   ORDER BY es.exam_date ASC''',
                (domain['id'],),
                fetch_all=True
            )

            for s in schedules:
                for key in ('exam_date', 'created_at'):
                    if s.get(key) and not isinstance(s[key], str):
                        try:
                            s[key] = s[key].strftime('%Y-%m-%d')
                        except:
                            s[key] = str(s[key])

            # Result stats
            total_results = db.execute_query(
                'SELECT COUNT(*) as cnt FROM exam_results WHERE domain_id = ?',
                (domain['id'],),
                fetch_one=True
            )
            passed_results = db.execute_query(
                f'SELECT COUNT(*) as cnt FROM exam_results WHERE domain_id = ? AND passed = {is_active_val}',
                (domain['id'],),
                fetch_one=True
            )

            # Pending (approved) students for this domain
            pending_exam = db.execute_query(
                '''SELECT COUNT(DISTINCT s.id) as cnt FROM students s
                   JOIN student_domains sd ON s.id = sd.student_id
                   WHERE sd.domain_id = ? AND s.account_status = 'approved' ''',
                (domain['id'],),
                fetch_one=True
            )

            overview.append({
                'domain': domain,
                'config': config,
                'schedules': schedules,
                'total_results': total_results['cnt'] if total_results else 0,
                'passed_results': passed_results['cnt'] if passed_results else 0,
                'pending_exam_students': pending_exam['cnt'] if pending_exam else 0
            })

        return jsonify({'overview': overview}), 200

    except Exception as e:
        print(f"Error getting exam overview: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/exams/config', methods=['POST'])
@require_admin_auth
def save_exam_config():
    """Create or update exam configuration for a domain"""
    try:
        data = request.get_json()
        domain_id = data.get('domain_id')
        max_marks = data.get('max_marks', 100)
        passing_marks = data.get('passing_marks', 40)
        cooldown_days = data.get('cooldown_days', 90)

        if not domain_id:
            return jsonify({'error': 'Domain ID is required'}), 400

        if not (1 <= max_marks <= 1000):
            return jsonify({'error': 'Max marks must be between 1 and 1000'}), 400
        if not (1 <= passing_marks <= max_marks):
            return jsonify({'error': f'Passing marks must be between 1 and {max_marks}'}), 400
        if not (1 <= cooldown_days <= 365):
            return jsonify({'error': 'Cooldown must be between 1 and 365 days'}), 400

        # Look up admin_id from admins table using session user_id
        admin_record = db.execute_query(
            'SELECT id FROM admins WHERE user_id = ?',
            (session.get('user_id'),),
            fetch_one=True
        )
        admin_id = admin_record['id'] if admin_record else None

        existing = db.execute_query(
            'SELECT id FROM exam_config WHERE domain_id = ?',
            (domain_id,),
            fetch_one=True
        )

        if existing:
            db.execute_query(
                '''UPDATE exam_config
                   SET max_marks = ?, passing_marks = ?, cooldown_days = ?, updated_by_admin_id = ?
                   WHERE domain_id = ?''',
                (max_marks, passing_marks, cooldown_days, admin_id, domain_id)
            )
        else:
            db.execute_query(
                '''INSERT INTO exam_config
                   (domain_id, max_marks, passing_marks, cooldown_days, updated_by_admin_id)
                   VALUES (?, ?, ?, ?, ?)''',
                (domain_id, max_marks, passing_marks, cooldown_days, admin_id)
            )

        log_activity('update_exam_config', 'exam', target_type='exam_config')
        return jsonify({'message': 'Exam configuration saved'}), 200

    except Exception as e:
        print(f"Error saving exam config: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/exams/schedule', methods=['POST'])
@require_admin_auth
def create_exam_schedule():
    """Create an exam schedule for a domain"""
    try:
        data = request.get_json()
        domain_id = data.get('domain_id')
        title = data.get('title', '').strip()
        exam_date = data.get('exam_date', '').strip()
        start_time = data.get('start_time', '').strip()
        end_time = data.get('end_time', '').strip()
        venue = data.get('venue', '').strip()
        venue_address = data.get('venue_address', '').strip()
        max_students = data.get('max_students', 50)
        instructions = data.get('instructions', '').strip()

        if not all([domain_id, title, exam_date, start_time, end_time, venue]):
            return jsonify({'error': 'Domain, title, date, time, and venue are required'}), 400

        # Validate date
        try:
            exam_dt = datetime.strptime(exam_date, '%Y-%m-%d')
        except ValueError:
            return jsonify({'error': 'Invalid date format (use YYYY-MM-DD)'}), 400

        if exam_dt.date() < datetime.now().date():
            return jsonify({'error': 'Exam date cannot be in the past'}), 400

        admin_rec = db.execute_query('SELECT id FROM admins WHERE user_id = ?', (session.get('user_id'),), fetch_one=True)
        admin_id = admin_rec['id'] if admin_rec else session.get('user_id')

        schedule_id = db.execute_query(
            '''INSERT INTO exam_schedules
               (domain_id, title, exam_date, start_time, end_time, venue, venue_address,
                max_students, instructions, created_by_admin_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (domain_id, title, exam_date, start_time, end_time, venue, venue_address,
             max_students, instructions, admin_id)
        )

        log_activity('create_exam_schedule', 'exam', target_type='exam_schedule', target_id=schedule_id, target_name=title, details=f'Date: {exam_date}, Venue: {venue}')
        return jsonify({'message': 'Exam schedule created', 'id': schedule_id}), 201

    except Exception as e:
        print(f"Error creating schedule: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/exams/schedule/<int:schedule_id>', methods=['DELETE'])
@require_admin_auth
def delete_exam_schedule(schedule_id):
    """Deactivate an exam schedule"""
    try:
        is_active_val = get_bool_literal(False)
        db.execute_query(
            f'UPDATE exam_schedules SET is_active = {is_active_val} WHERE id = ?',
            (schedule_id,)
        )
        log_activity('delete_exam_schedule', 'exam', target_type='exam_schedule', target_id=schedule_id)
        return jsonify({'message': 'Schedule deactivated'}), 200
    except Exception as e:
        print(f"Error deleting schedule: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/exams/schedule/<int:schedule_id>/registrations', methods=['GET'])
@require_admin_auth
def get_schedule_registrations(schedule_id):
    """Get all registered students for a schedule"""
    try:
        registrations = db.execute_query(
            '''SELECT er.*, s.full_name, s.wapl_id, s.phone, u.email, d.domain_name
               FROM exam_registrations er
               JOIN students s ON er.student_id = s.id
               JOIN users u ON s.user_id = u.id
               JOIN exam_schedules es ON er.schedule_id = es.id
               JOIN domains d ON es.domain_id = d.id
               WHERE er.schedule_id = ?
               ORDER BY er.seat_number ASC''',
            (schedule_id,),
            fetch_all=True
        )

        for r in registrations:
            if r.get('registered_at') and not isinstance(r['registered_at'], str):
                try:
                    r['registered_at'] = r['registered_at'].strftime('%Y-%m-%d %H:%M')
                except:
                    r['registered_at'] = str(r['registered_at'])

            # Check if result already entered
            result = db.execute_query(
                'SELECT id, marks_obtained, passed, remarks FROM exam_results WHERE student_id = ? AND schedule_id = ?',
                (r['student_id'], schedule_id),
                fetch_one=True
            )
            r['result'] = result

        return jsonify({'registrations': registrations}), 200

    except Exception as e:
        print(f"Error getting registrations: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/exams/enter-result', methods=['POST'])
@require_admin_auth
def enter_exam_result():
    """Manually enter exam result for a student"""
    try:
        data = request.get_json()
        student_id = data.get('student_id')
        schedule_id = data.get('schedule_id')
        marks_obtained = data.get('marks_obtained')
        remarks = data.get('remarks', '').strip()

        if not all([student_id, schedule_id, marks_obtained is not None]):
            return jsonify({'error': 'Student ID, schedule ID, and marks are required'}), 400

        marks_obtained = int(marks_obtained)

        # Get schedule + domain
        schedule = db.execute_query(
            'SELECT * FROM exam_schedules WHERE id = ?',
            (schedule_id,),
            fetch_one=True
        )
        if not schedule:
            return jsonify({'error': 'Schedule not found'}), 404

        domain_id = schedule['domain_id']

        # Get exam config for this domain
        config = db.execute_query(
            'SELECT * FROM exam_config WHERE domain_id = ?',
            (domain_id,),
            fetch_one=True
        )

        max_marks = config['max_marks'] if config else 100
        passing_marks = config['passing_marks'] if config else 40
        cooldown_days = config['cooldown_days'] if config else 90

        if marks_obtained < 0 or marks_obtained > max_marks:
            return jsonify({'error': f'Marks must be between 0 and {max_marks}'}), 400

        # Determine pass/fail
        passed = marks_obtained >= passing_marks
        passed_val = get_bool_literal(passed)
        admin_rec = db.execute_query('SELECT id FROM admins WHERE user_id = ?', (session.get('user_id'),), fetch_one=True)
        admin_id = admin_rec['id'] if admin_rec else session.get('user_id')

        # Check if result already exists
        existing = db.execute_query(
            'SELECT id, marks_obtained, passed FROM exam_results WHERE student_id = ? AND schedule_id = ?',
            (student_id, schedule_id),
            fetch_one=True
        )
        
        is_update = False
        if existing:
            # Update existing result
            is_update = True
            old_marks = existing['marks_obtained']
            db.execute_query(
                f'''UPDATE exam_results
                   SET marks_obtained = ?, max_marks = ?, passing_marks = ?,
                       passed = {passed_val}, remarks = ?, entered_by_admin_id = ?
                   WHERE id = ?''',
                (marks_obtained, max_marks, passing_marks, remarks, admin_id, existing['id'])
            )
        else:
            # Insert new result
            db.execute_query(
                f'''INSERT INTO exam_results
                   (student_id, schedule_id, domain_id, marks_obtained, max_marks,
                    passing_marks, passed, remarks, entered_by_admin_id)
                   VALUES (?, ?, ?, ?, ?, ?, {passed_val}, ?, ?)''',
                (student_id, schedule_id, domain_id, marks_obtained, max_marks,
                 passing_marks, remarks, admin_id)
            )

        # Update student status based on ALL domain results
        now = datetime.now()
        is_active_val = get_bool_literal(True)
        passed_val_true = get_bool_literal(True)
        passed_val_false = get_bool_literal(False)

        # ===== Per-domain cooldown handling =====
        if passed:
            # Student passed this domain — remove any cooldown for this domain
            db.execute_query(
                'DELETE FROM domain_cooldowns WHERE student_id = ? AND domain_id = ?',
                (student_id, domain_id)
            )
        else:
            # Student failed this domain — set a per-domain cooldown
            domain_cooldown_until = now + timedelta(days=cooldown_days)
            existing_cooldown = db.execute_query(
                'SELECT id FROM domain_cooldowns WHERE student_id = ? AND domain_id = ?',
                (student_id, domain_id),
                fetch_one=True
            )
            if existing_cooldown:
                db.execute_query(
                    'UPDATE domain_cooldowns SET cooldown_until = ?, failed_at = ? WHERE id = ?',
                    (domain_cooldown_until, now, existing_cooldown['id'])
                )
            else:
                db.execute_query(
                    'INSERT INTO domain_cooldowns (student_id, domain_id, cooldown_until, failed_at) VALUES (?, ?, ?, ?)',
                    (student_id, domain_id, domain_cooldown_until, now)
                )

        # Get all domains this student is enrolled in
        student_domains = db.execute_query(
            'SELECT domain_id FROM student_domains WHERE student_id = ?',
            (student_id,),
            fetch_all=True
        )
        total_domains = len(student_domains)
        domain_ids = [sd['domain_id'] for sd in student_domains]

        # Count how many domains the student has passed (latest result per domain)
        domains_passed = 0
        domains_failed = 0
        for did in domain_ids:
            best = db.execute_query(
                f'SELECT passed FROM exam_results WHERE student_id = ? AND domain_id = ? AND passed = {passed_val_true} LIMIT 1',
                (student_id, did),
                fetch_one=True
            )
            if best:
                domains_passed += 1
            else:
                # Check if they have any failed result for this domain
                failed = db.execute_query(
                    f'SELECT id FROM exam_results WHERE student_id = ? AND domain_id = ? AND passed = {passed_val_false} LIMIT 1',
                    (student_id, did),
                    fetch_one=True
                )
                if failed:
                    domains_failed += 1

        if domains_passed == total_domains:
            # Passed ALL domains — fully activate, clear all cooldowns
            db.execute_query(
                "UPDATE students SET account_status = 'active', cooldown_until = NULL WHERE id = ?",
                (student_id,)
            )
            db.execute_query(
                'DELETE FROM domain_cooldowns WHERE student_id = ?',
                (student_id,)
            )
            status_msg = 'PASSED — All domain exams cleared, account activated!'
        elif domains_passed > 0 and not passed:
            # Passed some domains but failed this one — account stays ACTIVE
            # Student can use the platform; only this domain is on cooldown
            db.execute_query(
                "UPDATE students SET account_status = 'active', cooldown_until = NULL WHERE id = ?",
                (student_id,)
            )
            domain_cooldown_date = (now + timedelta(days=cooldown_days)).strftime('%B %d, %Y')
            status_msg = f'FAILED this domain — Passed {domains_passed}/{total_domains} domains. Account active. Can reattempt this domain after {domain_cooldown_date}.'
        elif passed:
            # Passed this domain — activate account even if other domains pending
            db.execute_query(
                "UPDATE students SET account_status = 'active', cooldown_until = NULL WHERE id = ?",
                (student_id,)
            )
            if domains_passed == total_domains:
                db.execute_query(
                    'DELETE FROM domain_cooldowns WHERE student_id = ?',
                    (student_id,)
                )
                status_msg = 'PASSED — All domain exams cleared, account activated!'
            else:
                status_msg = f'PASSED this domain — {domains_passed}/{total_domains} domains cleared so far. Account active.'
        else:
            # Failed this domain and hasn't passed any domain yet
            if domains_failed == total_domains:
                # Failed ALL enrolled domains — lock account with global cooldown
                cooldown_until = now + timedelta(days=cooldown_days)
                db.execute_query(
                    "UPDATE students SET account_status = 'failed', cooldown_until = ? WHERE id = ?",
                    (cooldown_until, student_id)
                )
                status_msg = f'FAILED all domains — Cooldown until {cooldown_until.strftime("%B %d, %Y")}'
            else:
                # Failed some domains but still has unattempted domains — keep approved
                # Student can still take exams for other domains; only failed domain is on cooldown
                db.execute_query(
                    "UPDATE students SET account_status = 'approved', cooldown_until = NULL WHERE id = ?",
                    (student_id,)
                )
                domains_remaining = total_domains - domains_failed
                domain_cooldown_date = (now + timedelta(days=cooldown_days)).strftime('%B %d, %Y')
                status_msg = f'FAILED this domain — {domains_remaining} domain(s) still available to attempt. Can reattempt this domain after {domain_cooldown_date}.'

        action_word = 'updated' if is_update else 'entered'
        log_activity(f'{action_word}_exam_result', 'exam', target_type='student', target_id=student_id, details=f'Marks: {marks_obtained}/{max_marks}, Passed: {passed}' + (f' (was {old_marks})' if is_update else ''))

        return jsonify({
            'message': f'Result {action_word}: {status_msg}',
            'passed': passed,
            'marks_obtained': marks_obtained,
            'max_marks': max_marks,
            'passing_marks': passing_marks,
            'domains_passed': domains_passed,
            'total_domains': total_domains
        }), 200 if is_update else 201

    except Exception as e:
        print(f"Error entering result: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/exams/results', methods=['GET'])
@require_admin_auth
def get_exam_results():
    """Get all exam results with filters"""
    try:
        domain_id = request.args.get('domain_id')
        status = request.args.get('status')  # 'passed' or 'failed'

        is_active_val = get_bool_literal(True)
        is_false_val = get_bool_literal(False)

        query = '''SELECT er.*, s.full_name, s.wapl_id, d.domain_name, u.email,
                          es.title as schedule_title, es.exam_date, es.venue
                   FROM exam_results er
                   JOIN students s ON er.student_id = s.id
                   JOIN domains d ON er.domain_id = d.id
                   JOIN users u ON s.user_id = u.id
                   JOIN exam_schedules es ON er.schedule_id = es.id
                   WHERE 1=1'''
        params = []

        if domain_id:
            query += ' AND er.domain_id = ?'
            params.append(int(domain_id))

        if status == 'passed':
            query += f' AND er.passed = {is_active_val}'
        elif status == 'failed':
            query += f' AND er.passed = {is_false_val}'

        query += ' ORDER BY er.created_at DESC'

        results = db.execute_query(query, tuple(params), fetch_all=True)

        for r in results:
            for key in ('exam_date', 'created_at'):
                if r.get(key) and not isinstance(r[key], str):
                    try:
                        r[key] = r[key].strftime('%Y-%m-%d')
                    except:
                        r[key] = str(r[key])
            r['percentage'] = round((r['marks_obtained'] / r['max_marks']) * 100, 1) if r['max_marks'] > 0 else 0

        return jsonify({'results': results}), 200

    except Exception as e:
        print(f"Error getting exam results: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== ACTIVITY LOG ROUTES ====================


@admin_bp.route('/secure-admin-panel/wapl/activity-logs')
@require_admin_auth
def admin_activity_logs_page():
    """Admin activity logs page"""
    return render_template('admin/activity_logs.html')


@admin_bp.route('/api/admin/activity-logs', methods=['GET'])
@require_admin_auth
def get_activity_logs():
    """Get activity logs with filtering. Super admin sees all, regular admin sees own + student/HR logs"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        offset = (page - 1) * per_page

        # Filters
        category = request.args.get('category', '')
        action = request.args.get('action', '')
        user_role = request.args.get('user_role', '')
        search = request.args.get('search', '').strip()
        date_from = request.args.get('from', '')
        date_to = request.args.get('to', '')

        is_super = session.get('is_super_admin', False)
        admin_user_id = session.get('user_id')

        where_clauses = []
        params = []

        # Role-based filtering: regular admins only see their own logs + student/HR activity
        if not is_super:
            where_clauses.append("(al.user_id = ? OR al.user_role IN ('student', 'hr'))")
            params.append(admin_user_id)

        if category:
            where_clauses.append("al.category = ?")
            params.append(category)

        if action:
            where_clauses.append("al.action LIKE ?")
            params.append(f'%{action}%')

        if user_role:
            where_clauses.append("al.user_role = ?")
            params.append(user_role)

        if search:
            where_clauses.append("(al.user_name LIKE ? OR al.user_email LIKE ? OR al.action LIKE ? OR al.details LIKE ?)")
            params.extend([f'%{search}%'] * 4)

        if date_from:
            where_clauses.append("al.created_at >= ?")
            params.append(date_from)

        if date_to:
            where_clauses.append("al.created_at <= ?")
            params.append(date_to + ' 23:59:59')

        where_sql = ' AND '.join(where_clauses) if where_clauses else '1=1'

        # Get total count
        count_query = f"SELECT COUNT(*) as total FROM activity_logs al WHERE {where_sql}"
        count_result = db.execute_query(count_query, tuple(params), fetch_one=True)
        total = count_result['total'] if count_result else 0

        # Get logs
        query = f"""
            SELECT al.* FROM activity_logs al
            WHERE {where_sql}
            ORDER BY al.created_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([per_page, offset])
        logs = db.execute_query(query, tuple(params), fetch_all=True)

        # Format dates
        for log in logs:
            if log.get('created_at') and not isinstance(log['created_at'], str):
                try:
                    log['created_at'] = log['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                except:
                    log['created_at'] = str(log['created_at'])

        return jsonify({
            'logs': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200

    except Exception as e:
        print(f"Error getting activity logs: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== ADMIN PASSWORD & EMAIL CHANGE ====================


@admin_bp.route('/api/admin/change-email', methods=['POST'])
@require_admin_auth
def admin_change_email():
    """Allow admin to change their own email"""
    try:
        user_id = session['user_id']
        data = request.get_json()

        new_email = data.get('newEmail', '').strip().lower()
        password = data.get('password', '').strip()

        if not new_email or not password:
            return jsonify({'error': 'New email and password are required'}), 400

        # Basic email validation
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Verify password
        user = db.execute_query(
            'SELECT id, email, password_hash FROM users WHERE id = ?',
            (user_id,),
            fetch_one=True
        )
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user['email'] == new_email:
            return jsonify({'error': 'New email is the same as current email'}), 400

        if not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Incorrect password'}), 400

        # Check if email already taken
        existing = db.execute_query(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            (new_email, user_id),
            fetch_one=True
        )
        if existing:
            return jsonify({'error': 'Email is already in use'}), 400

        # Update email
        db.execute_query(
            'UPDATE users SET email = ? WHERE id = ?',
            (new_email, user_id)
        )

        # Update session
        session['email'] = new_email

        log_activity('change_email', 'admin', target_type='admin', target_id=user_id,
                     details=f'Email changed from {user["email"]} to {new_email}')

        return jsonify({'message': 'Email changed successfully', 'newEmail': new_email}), 200

    except Exception as e:
        print(f'Error changing admin email: {e}')
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/change-password', methods=['POST'])
@require_admin_auth
def admin_change_password():
    """Allow admin to change their own password"""
    try:
        user_id = session['user_id']
        data = request.get_json()

        current_password = data.get('currentPassword', '').strip()
        new_password = data.get('newPassword', '').strip()
        confirm_password = data.get('confirmPassword', '').strip()

        if not current_password or not new_password or not confirm_password:
            return jsonify({'error': 'All fields are required'}), 400

        if new_password != confirm_password:
            return jsonify({'error': 'New passwords do not match'}), 400

        if len(new_password) < 6:
            return jsonify({'error': 'New password must be at least 6 characters'}), 400

        if current_password == new_password:
            return jsonify({'error': 'New password must be different from current password'}), 400

        # Verify current password
        user = db.execute_query(
            'SELECT id, password_hash FROM users WHERE id = ?',
            (user_id,),
            fetch_one=True
        )
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not check_password_hash(user['password_hash'], current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400

        # Update password
        new_hash = generate_password_hash(new_password)
        db.execute_query(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_hash, user_id)
        )

        log_activity('change_password', 'admin', target_type='admin', target_id=user_id, details='Password changed by admin')

        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        print(f'Error changing admin password: {e}')
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/activity-logs/stats', methods=['GET'])
@require_admin_auth
def get_activity_logs_stats():
    """Get activity log statistics for dashboard"""
    try:
        is_super = session.get('is_super_admin', False)
        admin_user_id = session.get('user_id')

        role_filter = ""
        params = []
        if not is_super:
            role_filter = "AND (user_id = ? OR user_role IN ('student', 'hr'))"
            params = [admin_user_id]

        # Today's activity count (using IST date, not UTC)
        from zoneinfo import ZoneInfo
        ist_today = datetime.now(ZoneInfo('Asia/Kolkata')).strftime('%Y-%m-%d')
        today_count = db.execute_query(
            f"SELECT COUNT(*) as cnt FROM activity_logs WHERE DATE(created_at) = ? {role_filter}",
            tuple([ist_today] + params), fetch_one=True
        )

        # Activity by category
        categories = db.execute_query(
            f"SELECT category, COUNT(*) as cnt FROM activity_logs WHERE 1=1 {role_filter} GROUP BY category ORDER BY cnt DESC",
            tuple(params), fetch_all=True
        )

        # Activity by role
        roles = db.execute_query(
            f"SELECT user_role, COUNT(*) as cnt FROM activity_logs WHERE 1=1 {role_filter} GROUP BY user_role ORDER BY cnt DESC",
            tuple(params), fetch_all=True
        )

        # Recent 10 logs
        recent = db.execute_query(
            f"SELECT * FROM activity_logs WHERE 1=1 {role_filter} ORDER BY created_at DESC LIMIT 10",
            tuple(params), fetch_all=True
        )
        for log in recent:
            if log.get('created_at') and not isinstance(log['created_at'], str):
                try:
                    log['created_at'] = log['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                except:
                    log['created_at'] = str(log['created_at'])

        return jsonify({
            'today_count': today_count['cnt'] if today_count else 0,
            'by_category': categories or [],
            'by_role': roles or [],
            'recent': recent or []
        }), 200

    except Exception as e:
        print(f"Error getting activity log stats: {e}")
        return jsonify({'error': str(e)}), 500
