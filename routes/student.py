
from flask import Blueprint, request, jsonify, session, send_file, redirect, url_for, render_template
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from database import db, get_bool_literal, get_subscription_expiry, get_student_subscription_state
from utils import (
    generate_wapl_id, generate_otp, sanitize_input,
    allowed_file, save_uploaded_file, log_activity
)
from storage import Storage
import os
import json

student_bp = Blueprint('student', __name__)

def require_student_auth(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'student':
            # Check if it's an API request
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Student access required'}), 403
            # Otherwise redirect to login
            return redirect(url_for('auth.login_page'))
        
        # Check if student account is active
        student = db.execute_query(
            'SELECT id, account_status FROM students WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )
        
        if not student:
            session.clear()
            return jsonify({'error': 'Student account not found'}), 404

        subscription_state = get_student_subscription_state(student['id'])
        if subscription_state:
            student['account_status'] = subscription_state['account_status']
        
        if student['account_status'] not in ('active', 'approved'):
            if student['account_status'] == 'expired':
                session.clear()
                return jsonify({'error': 'Your subscription has expired. Please renew your domain payment to continue access.'}), 403
            session.clear()
            return jsonify({'error': 'Your account is pending admin approval or has been suspended. Please contact the administrator.'}), 403
        
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# ==================== REGISTRATION & OTP ROUTES ====================

@student_bp.route('/api/student/register', methods=['POST'])
def student_register():
    """Student registration - Step 1: Generate and display OTP"""
    try:
        data = request.get_json()
        
        # Extract and validate data
        email = sanitize_input(data.get('email', '')).strip().lower()
        password = data.get('password', '')
        full_name = sanitize_input(data.get('fullName', '')).strip()
        phone = sanitize_input(data.get('phone', '')).strip()
        address = sanitize_input(data.get('address', '')).strip()
        domain_ids = data.get('domainIds', [])
        
        # Validation
        if not all([email, password, full_name, phone]):
            return jsonify({'error': 'Email, password, full name, and phone are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        if not domain_ids or len(domain_ids) == 0:
            return jsonify({'error': 'Please select at least one domain'}), 400
        
        # Check if email already exists
        existing = db.execute_query(
            'SELECT id FROM users WHERE email = ?',
            (email,),
            fetch_one=True
        )
        
        if existing:
            return jsonify({'error': 'Email already registered'}), 400
        
        # Generate OTP
        otp = generate_otp()
        otp_expiry = datetime.now() + timedelta(minutes=10)
        
        # Store registration data in session (temporary)
        session['registration_data'] = {
            'email': email,
            'password_hash': generate_password_hash(password),
            'full_name': full_name,
            'phone': phone,
            'address': address,
            'domain_ids': domain_ids,
            'otp': otp,
            'otp_expiry': otp_expiry.isoformat(),
            'otp_verified': False
        }
        
        # Print OTP to console (for development)
        print("\n" + "="*60)
        print(f"📧 STUDENT REGISTRATION OTP")
        print(f"🔐 Email: {email}")
        print(f"🔢 OTP Code: {otp}")
        print(f"⏰ Valid until: {otp_expiry.strftime('%I:%M %p')}")
        print(f"⏱️  Expires in: 10 minutes")
        print("="*60 + "\n")
        
        return jsonify({
            'message': 'OTP generated successfully. Check your Flask console.',
            'email': email,
            'redirect': '/verify-otp'
        }), 200
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500


@student_bp.route('/api/student/verify-otp', methods=['POST'])
def verify_student_otp():
    """Verify OTP and complete registration"""
    try:
        data = request.get_json()
        entered_otp = data.get('otp', '').strip()
        
        if not entered_otp:
            return jsonify({'error': 'OTP is required'}), 400
        
        # Get registration data from session
        reg_data = session.get('registration_data')
        if not reg_data:
            return jsonify({'error': 'Registration session expired. Please register again.'}), 400
        
        # Check if OTP is expired
        otp_expiry = datetime.fromisoformat(reg_data['otp_expiry'])
        if datetime.now() > otp_expiry:
            session.pop('registration_data', None)
            return jsonify({'error': 'OTP has expired. Please register again.'}), 400
        
        # Verify OTP
        if entered_otp != reg_data['otp']:
            return jsonify({'error': 'Invalid OTP. Please try again.'}), 400
        
        # OTP is correct - Create user account
        password_hash = reg_data['password_hash']
        
        try:
            # Create user
            insert_user_sql = "INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, 'student', ?)"
            user_id = db.execute_query(insert_user_sql, (reg_data['email'], password_hash, True))
            
            # Generate WAPL ID with domain-based code
            wapl_id = generate_wapl_id(domain_ids=reg_data['domain_ids'])
            
            # Create student profile with PENDING status
            insert_student_sql = """INSERT INTO students 
                   (user_id, wapl_id, full_name, phone, address, account_status) 
                   VALUES (?, ?, ?, ?, ?, 'pending')"""
            student_id = db.execute_query(
                insert_student_sql,
                (user_id, wapl_id, reg_data['full_name'], reg_data['phone'], reg_data['address'])
            )
            
            # Assign domains (multiple domains)
            for domain_id in reg_data['domain_ids']:
                try:
                    db.execute_query(
                        "INSERT INTO student_domains (student_id, domain_id, expires_at) VALUES (?, ?, ?)",
                        (student_id, domain_id, get_subscription_expiry(datetime.now()))
                    )
                except Exception as e:
                    print(f"Domain assignment error: {e}")
                    # Continue assigning other domains

            db.execute_query(
                "UPDATE students SET account_status = 'active' WHERE id = ? AND account_status = 'expired'",
                (student_id,)
            )
            
            # Clear registration data from session
            session.pop('registration_data', None)
            
            # Print success message to console
            print("\n" + "="*60)
            print(f"✅ REGISTRATION SUCCESSFUL!")
            print(f"📧 Email: {reg_data['email']}")
            print(f"🎓 WAPL ID: {wapl_id}")
            print(f"📋 Status: PENDING (Awaiting admin approval)")
            print("="*60 + "\n")
            
            return jsonify({
                'message': 'Registration successful! Your account is pending admin approval.',
                'wapl_id': wapl_id,
                'status': 'pending',
                'redirect': '/login'
            }), 201
            
        except Exception as e:
            print(f"Database error during registration: {e}")
            return jsonify({'error': 'A database error occurred during registration. Please try again.'}), 500
            
    except Exception as e:
        print(f"OTP verification error: {e}")
        return jsonify({'error': str(e)}), 500


@student_bp.route('/api/student/resend-otp', methods=['POST'])
def resend_student_otp():
    """Resend OTP for registration"""
    try:
        reg_data = session.get('registration_data')
        if not reg_data:
            return jsonify({'error': 'Registration session expired. Please register again.'}), 400
        
        # Generate new OTP
        otp = generate_otp()
        otp_expiry = datetime.now() + timedelta(minutes=10)
        
        # Update session
        reg_data['otp'] = otp
        reg_data['otp_expiry'] = otp_expiry.isoformat()
        session['registration_data'] = reg_data
        
        # Print new OTP to console
        print("\n" + "="*60)
        print(f"🔄 RESEND OTP REQUEST")
        print(f"📧 Email: {reg_data['email']}")
        print(f"🔢 New OTP Code: {otp}")
        print(f"⏰ Valid until: {otp_expiry.strftime('%I:%M %p')}")
        print("="*60 + "\n")
        
        return jsonify({
            'message': 'New OTP generated. Check your Flask console.',
            'email': reg_data['email']
        }), 200
        
    except Exception as e:
        print(f"Resend OTP error: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== STUDENT PROFILE ROUTES ====================

# ==================== STUDENT PROJECT PORTFOLIO ROUTES ====================

import uuid

@student_bp.route('/api/student/projects', methods=['GET'])
@require_student_auth
def get_student_projects():
    """List all projects for the logged-in student"""
    try:
        user_id = session['user_id']
        student = db.execute_query('SELECT id FROM students WHERE user_id = ?', (user_id,), fetch_one=True)
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        projects = db.execute_query(
            'SELECT * FROM student_projects WHERE student_id = ? ORDER BY created_at DESC',
            (student['id'],),
            fetch_all=True
        )
        return jsonify({'projects': [dict(p) for p in projects]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@student_bp.route('/api/student/projects', methods=['POST'])
@require_student_auth
def upload_student_project():
    """Upload a new project (title, description, image)"""
    try:
        user_id = session['user_id']
        student = db.execute_query('SELECT id FROM students WHERE user_id = ?', (user_id,), fetch_one=True)
        if not student:
            return jsonify({'error': 'Student not found'}), 404

        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        image = request.files.get('image')

        if not title:
            return jsonify({'error': 'Project title is required'}), 400

        image_path = None
        if image and allowed_file(image.filename):
            filename = secure_filename(f"{uuid.uuid4().hex}_{image.filename}")
            upload_folder = os.path.join('uploads', 'projects')
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            image.save(file_path)
            image_path = f'uploads/projects/{filename}'

        db.execute_query(
            'INSERT INTO student_projects (student_id, title, description, image_path, created_at) VALUES (?, ?, ?, ?, ?)',
            (student['id'], title, description, image_path, datetime.now())
        )
        return jsonify({'message': 'Project uploaded successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@student_bp.route('/api/student/projects/<int:project_id>', methods=['DELETE'])
@require_student_auth
def delete_student_project(project_id):
    """Delete a project by ID (only if owned by student)"""
    try:
        user_id = session['user_id']
        student = db.execute_query('SELECT id FROM students WHERE user_id = ?', (user_id,), fetch_one=True)
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        project = db.execute_query('SELECT * FROM student_projects WHERE id = ? AND student_id = ?', (project_id, student['id']), fetch_one=True)
        if not project:
            return jsonify({'error': 'Project not found or not owned by you'}), 404
        # Delete image file if exists
        if project['image_path']:
            image_file = project['image_path'].replace('/', os.sep).replace('\\', os.sep)
            if os.path.exists(image_file):
                os.remove(image_file)
        db.execute_query('DELETE FROM student_projects WHERE id = ?', (project_id,))
        return jsonify({'message': 'Project deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@student_bp.route('/api/student/profile', methods=['GET'])
@require_student_auth
def get_profile():
    try:
        user_id = session['user_id']
        
        student = db.execute_query(
            '''SELECT s.*, u.email 
               FROM students s
               LEFT JOIN users u ON s.user_id = u.id
               WHERE s.user_id = ?''',
            (user_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student profile not found'}), 404
        
        # Get student's domains (multiple)
        domains = db.execute_query(
            '''SELECT d.id, d.domain_name 
               FROM student_domains sd
               JOIN domains d ON sd.domain_id = d.id
               WHERE sd.student_id = ?
               ORDER BY d.domain_name''',
            (student['id'],),
            fetch_all=True
        )
        
        # Get assigned HR if any
        hr = None
        recruitment_status = None
        if student['assigned_hr_id']:
            hr = db.execute_query(
                '''SELECT h.*, u.email 
                   FROM hrs h
                   LEFT JOIN users u ON h.user_id = u.id
                   WHERE h.id = ?''',
                (student['assigned_hr_id'],),
                fetch_one=True
            )
            
            # Get recruitment status
            recruitment_status = db.execute_query(
                '''SELECT status, notes, updated_at 
                   FROM recruitment_status 
                   WHERE student_id = ? AND hr_id = ?''',
                (student['id'], student['assigned_hr_id']),
                fetch_one=True
            )
        
        # Parse JSON fields
        profile = dict(student)
        profile['education_details'] = json.loads(student['education_details']) if student['education_details'] else []
        profile['skills'] = json.loads(student['skills']) if student['skills'] else []
        profile['projects'] = json.loads(student['projects']) if student['projects'] else []
        profile['domains'] = [dict(d) for d in domains] if domains else []
        profile['domain_name'] = ', '.join([d['domain_name'] for d in domains]) if domains else 'N/A'
        profile['assigned_hr'] = dict(hr) if hr else None
        profile['recruitment_status'] = dict(recruitment_status) if recruitment_status else None
        
        return jsonify(profile), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@student_bp.route('/api/student/profile', methods=['PUT'])
@require_student_auth
def update_profile():
    try:
        user_id = session['user_id']
        data = request.get_json()
        
        # Update basic fields
        updates = []
        params = []
        
        if 'full_name' in data:
            updates.append('full_name = ?')
            params.append(sanitize_input(data['full_name']))
        
        if 'phone' in data:
            updates.append('phone = ?')
            params.append(sanitize_input(data['phone']))
        
        if 'address' in data:
            updates.append('address = ?')
            params.append(sanitize_input(data['address']))
        
        if 'education_details' in data:
            updates.append('education_details = ?')
            params.append(json.dumps(data['education_details']))
        
        if 'skills' in data:
            updates.append('skills = ?')
            params.append(json.dumps(data['skills']))
        
        if 'projects' in data:
            updates.append('projects = ?')
            params.append(json.dumps(data['projects']))
        
        if updates:
            params.append(user_id)
            query = f"UPDATE students SET {', '.join(updates)} WHERE user_id = ?"
            db.execute_query(query, tuple(params))
        
        # Handle domain updates (multiple domains)
        if 'domain_ids' in data:
            domain_ids = data['domain_ids']
            
            # Get student ID
            student = db.execute_query(
                'SELECT id FROM students WHERE user_id = ?',
                (user_id,),
                fetch_one=True
            )
            
            if student:
                # Delete existing domain associations
                db.execute_query(
                    'DELETE FROM student_domains WHERE student_id = ?',
                    (student['id'],)
                )
                
                # Insert new domain associations
                for domain_id in domain_ids:
                    db.execute_query(
                        'INSERT INTO student_domains (student_id, domain_id, expires_at) VALUES (?, ?, ?)',
                        (student['id'], domain_id, get_subscription_expiry(datetime.now()))
                    )

                subscription_state = get_student_subscription_state(student['id'])
                if subscription_state and subscription_state['account_status'] == 'expired':
                    db.execute_query("UPDATE students SET account_status = 'active' WHERE id = ?", (student['id'],))
        
        log_activity('Profile updated', 'student', target_type='student', target_id=user_id, details=f'Fields updated: {", ".join(updates) if updates else "domains"}')

        return jsonify({'message': 'Profile updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@student_bp.route('/api/student/upload-photo', methods=['POST'])
@require_student_auth
def upload_photo():
    try:
        user_id = session['user_id']
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        allowed_extensions = {'jpg', 'jpeg', 'png'}
        if not allowed_file(file.filename, allowed_extensions):
            return jsonify({'error': 'Invalid file type. Only JPG, JPEG, PNG allowed'}), 400
        
        # Check file size (5MB)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 5 * 1024 * 1024:
            return jsonify({'error': 'File size exceeds 5MB limit'}), 400
        
        # Get student ID
        student = db.execute_query(
            'SELECT id, profile_pic FROM students WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Delete old profile pic if exists
        if student['profile_pic']:
            old_pic_path = os.path.join('uploads/profile_pics', student['profile_pic'])
            if os.path.exists(old_pic_path):
                try:
                    Storage.delete_file(student['profile_pic'])
                    print(f"✅ Deleted profile picture: {student['profile_pic']}")
                except Exception as e:
                    print(f"Error deleting old profile pic: {e}")
        
        # Save new file
        filepath = save_uploaded_file(
            file,
            'uploads/profile_pics',
            student['id'],
            'photo'
        )
        
        # Update database
        db.execute_query(
            'UPDATE students SET profile_pic = ? WHERE id = ?',
            (filepath, student['id'])
        )
        
        log_activity('Profile photo uploaded', 'student', target_type='student', target_id=user_id, details=f'File: {filepath}')

        return jsonify({'message': 'Profile picture uploaded successfully', 'path': filepath}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@student_bp.route('/api/student/delete-photo', methods=['DELETE'])
@require_student_auth
def delete_photo():
    try:
        user_id = session['user_id']
        
        # Get student
        student = db.execute_query(
            'SELECT id, profile_pic FROM students WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Delete the file from filesystem if it exists
        if student['profile_pic']:
            try:
                Storage.delete_file(student['profile_pic'])
                print(f"✅ Deleted profile picture: {student['profile_pic']}")
            except Exception as e:
                print(f"❌ Error deleting file: {e}")
        
        # Remove from database
        db.execute_query(
            'UPDATE students SET profile_pic = NULL WHERE id = ?',
            (student['id'],)
        )
        
        log_activity('Profile photo deleted', 'student', target_type='student', target_id=user_id)

        return jsonify({'message': 'Profile picture deleted successfully'}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@student_bp.route('/api/student/upload-resume', methods=['POST'])
@require_student_auth
def upload_resume():
    try:
        user_id = session['user_id']
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        allowed_extensions = {'pdf', 'doc', 'docx'}
        if not allowed_file(file.filename, allowed_extensions):
            return jsonify({'error': 'Invalid file type. Only PDF, DOC, DOCX allowed'}), 400
        
        # Check file size (10MB)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 10 * 1024 * 1024:
            return jsonify({'error': 'File size exceeds 10MB limit'}), 400
        
        # Get student ID
        student = db.execute_query(
            'SELECT id, resume FROM students WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Delete old resume if exists
        if student['resume']:
            try:
                Storage.delete_file(student['resume'])
            except Exception as e:
                print(f"Error deleting old resume: {e}")
        
        # Save new file
        filepath = save_uploaded_file(
            file,
            'uploads/resumes',
            student['id'],
            'resume'
        )
        
        # Update database
        db.execute_query(
            'UPDATE students SET resume = ? WHERE id = ?',
            (filepath, student['id'])
        )
        
        log_activity('Resume uploaded', 'student', target_type='student', target_id=user_id, details=f'File: {filepath}')

        return jsonify({'message': 'Resume uploaded successfully', 'path': filepath}), 200
        
    except Exception as e:
        print(f"UPLOAD ERROR: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@student_bp.route('/api/student/delete-resume', methods=['DELETE'])
@require_student_auth
def delete_resume():
    try:
        user_id = session['user_id']
        
        # Get student
        student = db.execute_query(
            'SELECT id, resume FROM students WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Delete the file from filesystem if it exists
        if student['resume']:
            try:
                Storage.delete_file(student['resume'])
                print(f"✅ Deleted resume: {student['resume']}")
            except Exception as e:
                print(f"❌ Error deleting file: {e}")
        
        # Remove from database
        db.execute_query(
            'UPDATE students SET resume = NULL WHERE id = ?',
            (student['id'],)
        )
        
        log_activity('Resume deleted', 'student', target_type='student', target_id=user_id)

        return jsonify({'message': 'Resume deleted successfully'}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== CERTIFICATE ROUTES ====================

@student_bp.route('/api/student/certificate', methods=['GET'])
@require_student_auth
def get_certificate():
    try:
        user_id = session['user_id']
        is_active_val = get_bool_literal(True)
        
        # Get student
        student = db.execute_query(
            'SELECT id FROM students WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Get certificate
        certificate = db.execute_query(
            f'''SELECT * FROM certificates 
               WHERE student_id = ? AND is_active = {is_active_val}
               ORDER BY issue_date DESC LIMIT 1''',
            (student['id'],),
            fetch_one=True
        )
        
        if not certificate:
            return jsonify({'error': 'No certificate found. Certificates are issued by admin after approval.'}), 404
        
        cert_data = dict(certificate)
        
        # Check if expired
        if cert_data.get('expiry_date'):
            try:
                # Handle different datetime formats
                expiry = cert_data['expiry_date']
                if isinstance(expiry, str):
                    expiry = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
                cert_data['is_valid'] = expiry > datetime.now(expiry.tzinfo) if expiry.tzinfo else expiry > datetime.now()
            except Exception as date_err:
                print(f"Date parsing error: {date_err}")
                cert_data['is_valid'] = True
        else:
            cert_data['is_valid'] = True
        
        # Convert datetime objects to strings for JSON
        for key in ['issue_date', 'expiry_date', 'created_at']:
            if key in cert_data and cert_data[key] and not isinstance(cert_data[key], str):
                cert_data[key] = cert_data[key].isoformat()
        
        return jsonify(cert_data), 200
        
    except Exception as e:
        print(f"Error getting certificate: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@student_bp.route('/api/student/certificate/download', methods=['GET'])
@require_student_auth
def download_certificate():
    try:
        user_id = session['user_id']
        is_active_val = get_bool_literal(True)
        
        # Get student
        student = db.execute_query(
            'SELECT id FROM students WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Get certificate
        certificate = db.execute_query(
            f'''SELECT * FROM certificates 
               WHERE student_id = ? AND is_active = {is_active_val}
               ORDER BY issue_date DESC LIMIT 1''',
            (student['id'],),
            fetch_one=True
        )
        
        if not certificate:
            return jsonify({'error': 'No certificate found'}), 404
        
        pdf_path = certificate['pdf_path']
        
        
        if not pdf_path:
             return jsonify({'error': 'Certificate file not found'}), 404
             
        # If it's a URL (Supabase), redirect
        if pdf_path.startswith('http'):
            log_activity('Certificate downloaded', 'certificate', target_type='certificate', target_id=certificate['id'], target_name=certificate['certificate_unique_id'])
            return redirect(pdf_path)
            
        # If local path, check existence
        if not os.path.exists(pdf_path):
            return jsonify({'error': 'Certificate file not found'}), 404
        
        log_activity('Certificate downloaded', 'certificate', target_type='certificate', target_id=certificate['id'], target_name=certificate['certificate_unique_id'])

        return send_file(
            pdf_path, 
            as_attachment=True, 
            download_name=f"certificate_{certificate['certificate_unique_id']}.pdf"
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== PASSWORD CHANGE ====================

@student_bp.route('/api/student/change-password', methods=['POST'])
@require_student_auth
def student_change_password():
    """Allow student to change their own password"""
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

        log_activity('change_password', 'student', target_type='student', target_id=user_id, details='Password changed by student')

        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        print(f'Error changing student password: {e}')
        return jsonify({'error': str(e)}), 500


# ==================== DOMAIN ROUTES ====================

@student_bp.route('/api/domains/active', methods=['GET'])
def get_active_domains():
    """Get all active domains for registration"""
    try:
        is_active_val = get_bool_literal(True)
        domains = db.execute_query(
            f'SELECT id, domain_name FROM domains WHERE is_active = {is_active_val} ORDER BY domain_name',
            fetch_all=True
        )
        
        return jsonify([dict(d) for d in domains]), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== PAGE ROUTES ====================

@student_bp.route('/student/dashboard')
@require_student_auth
def student_dashboard():
    return render_template('student/dashboard.html')

@student_bp.route('/student/profile')
@require_student_auth
def student_profile():
    return render_template('student/profile.html')

@student_bp.route('/student/certificate')
@require_student_auth
def student_certificate():
    return render_template('student/certificate.html')


# ==================== HR CHAT (Student) ====================


def _get_student_row_for_session():
    return db.execute_query(
        'SELECT id, assigned_hr_id, full_name, wapl_id, account_status FROM students WHERE user_id = ?',
        (session['user_id'],),
        fetch_one=True
    )


@student_bp.route('/api/student/messages/hr', methods=['GET'])
@require_student_auth
def student_get_hr_messages():
    try:
        student = _get_student_row_for_session()
        if not student:
            return jsonify({'error': 'Student not found'}), 404

        if not student.get('assigned_hr_id'):
            return jsonify({'assigned': False, 'messages': []}), 200

        hr = db.execute_query(
            '''SELECT h.id AS hr_id, h.full_name, h.company_name, u.email
               FROM hrs h
               JOIN users u ON u.id = h.user_id
               WHERE h.id = ?''',
            (student['assigned_hr_id'],),
            fetch_one=True
        )
        if not hr:
            return jsonify({'assigned': False, 'messages': []}), 200

        msgs = db.execute_query(
            '''SELECT id, sender_role, message_text, is_read, read_at, created_at
               FROM hr_student_messages
               WHERE hr_id = ? AND student_id = ?
               ORDER BY id ASC''',
            (hr['hr_id'], student['id']),
            fetch_all=True
        ) or []

        return jsonify({'assigned': True, 'hr': hr, 'messages': msgs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@student_bp.route('/api/student/messages/hr', methods=['POST'])
@require_student_auth
def student_send_hr_message():
    try:
        student = _get_student_row_for_session()
        if not student:
            return jsonify({'error': 'Student not found'}), 404

        hr_id = student.get('assigned_hr_id')
        if not hr_id:
            return jsonify({'error': 'No HR assigned to you'}), 400

        data = request.get_json() or {}
        message_text = sanitize_input((data.get('message') or '').strip())
        if not message_text:
            return jsonify({'error': 'Message is required'}), 400
        if len(message_text) > 2000:
            return jsonify({'error': 'Message too long (max 2000 chars)'}), 400

        db.execute_query(
            '''INSERT INTO hr_student_messages (student_id, hr_id, sender_role, message_text, is_read)
               VALUES (?, ?, 'student', ?, ?)''',
            (student['id'], hr_id, message_text, False)
        )
        log_activity('student_message_sent', 'student', target_type='hr', target_id=hr_id, details='Student sent a chat message')
        return jsonify({'message': 'Sent'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@student_bp.route('/api/student/messages/hr/read', methods=['POST'])
@require_student_auth
def student_mark_hr_messages_read():
    try:
        student = _get_student_row_for_session()
        if not student:
            return jsonify({'error': 'Student not found'}), 404

        hr_id = student.get('assigned_hr_id')
        if not hr_id:
            return jsonify({'message': 'No HR assigned'}), 200

        is_true = get_bool_literal(True)
        is_false = get_bool_literal(False)
        db.execute_query(
            f"""UPDATE hr_student_messages
                SET is_read = {is_true}, read_at = ?
                WHERE hr_id = ? AND student_id = ? AND sender_role = 'hr' AND is_read = {is_false}""",
            (datetime.now(), hr_id, student['id'])
        )
        return jsonify({'message': 'Marked read'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@student_bp.route('/student/messages')
@require_student_auth
def student_messages_page():
    return render_template('student/messages.html')
