from flask import Blueprint, request, jsonify, session, redirect, url_for, send_file, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
from database import db, get_agg_func, get_bool_literal
from utils import (sanitize_input, generate_certificate_id, generate_qr_code, generate_certificate_pdf,
    get_student_notification_info, send_student_recruitment_email, send_student_certificate_email, log_activity)
from storage import Storage
import json
import os

hr_bp = Blueprint('hr', __name__)


def _get_hr_profile(user_id):
    return db.execute_query(
        'SELECT * FROM hrs WHERE user_id = ?',
        (user_id,),
        fetch_one=True
    )


def require_hr_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'hr':
            from flask import redirect, url_for, request
            # Check if it's an API request
            if request.path.startswith('/api/'):
                return jsonify({'error': 'HR access required'}), 403
            # Otherwise redirect to login
            return redirect(url_for('auth.hr_login_page'))

        hr = _get_hr_profile(session['user_id'])
        if not hr or (hr.get('status') or '').lower() != 'approved':
            if request.path.startswith('/api/'):
                status = hr.get('status') if hr else 'missing'
                if status == 'pending':
                    return jsonify({'error': 'Account pending admin approval'}), 403
                if status == 'rejected':
                    return jsonify({'error': 'Account rejected. Please contact admin.'}), 403
                return jsonify({'error': 'HR account is not approved'}), 403
            session.clear()
            return redirect(url_for('auth.hr_login_page'))
        return f(*args, **kwargs)
    return wrapper

def _get_hr_id_for_session():
    hr = db.execute_query(
        'SELECT id, full_name FROM hrs WHERE user_id = ?',
        (session['user_id'],),
        fetch_one=True
    )
    return hr


@hr_bp.route('/api/hr/messages/conversations', methods=['GET'])
@require_hr_auth
def hr_message_conversations():
    """List assigned students with last message + unread counts."""
    try:
        hr = _get_hr_id_for_session()
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404

        hr_id = hr['id']
        students = db.execute_query(
            '''SELECT s.id AS student_id, s.full_name, s.wapl_id, u.email
               FROM students s
               JOIN users u ON u.id = s.user_id
               WHERE s.assigned_hr_id = ? AND s.account_status IN ('active','approved')
               ORDER BY s.full_name''',
            (hr_id,),
            fetch_all=True
        ) or []

        result = []
        for s in students:
            last_msg = db.execute_query(
                '''SELECT message_text, sender_role, created_at
                   FROM hr_student_messages
                   WHERE hr_id = ? AND student_id = ?
                   ORDER BY id DESC
                   LIMIT 1''',
                (hr_id, s['student_id']),
                fetch_one=True
            )
            unread = db.execute_query(
                '''SELECT COUNT(*) AS cnt
                   FROM hr_student_messages
                   WHERE hr_id = ? AND student_id = ? AND sender_role = 'student'
                     AND is_read = ?''',
                (hr_id, s['student_id'], False),
                fetch_one=True
            )
            item = dict(s)
            item['last_message'] = last_msg['message_text'] if last_msg else ''
            item['last_sender_role'] = last_msg['sender_role'] if last_msg else ''
            item['last_at'] = last_msg['created_at'] if last_msg else None
            item['unread_count'] = (unread or {}).get('cnt', 0) or 0
            result.append(item)

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@hr_bp.route('/api/hr/messages/<int:student_id>', methods=['GET'])
@require_hr_auth
def hr_get_messages(student_id):
    try:
        hr = _get_hr_id_for_session()
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404

        hr_id = hr['id']
        assigned = db.execute_query(
            "SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?",
            (student_id, hr_id),
            fetch_one=True
        )
        if not assigned:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404

        msgs = db.execute_query(
            '''SELECT id, sender_role, message_text, is_read, read_at, created_at
               FROM hr_student_messages
               WHERE hr_id = ? AND student_id = ?
               ORDER BY id ASC''',
            (hr_id, student_id),
            fetch_all=True
        ) or []
        return jsonify(msgs), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@hr_bp.route('/api/hr/messages/<int:student_id>', methods=['POST'])
@require_hr_auth
def hr_send_message(student_id):
    try:
        hr = _get_hr_id_for_session()
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404

        hr_id = hr['id']
        assigned = db.execute_query(
            "SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?",
            (student_id, hr_id),
            fetch_one=True
        )
        if not assigned:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404

        data = request.get_json() or {}
        message_text = sanitize_input((data.get('message') or '').strip())
        if not message_text:
            return jsonify({'error': 'Message is required'}), 400
        if len(message_text) > 2000:
            return jsonify({'error': 'Message too long (max 2000 chars)'}), 400

        db.execute_query(
            '''INSERT INTO hr_student_messages (student_id, hr_id, sender_role, message_text, is_read)
               VALUES (?, ?, 'hr', ?, ?)''',
            (student_id, hr_id, message_text, False)
        )
        log_activity('hr_message_sent', 'hr', target_type='student', target_id=student_id, details='HR sent a chat message')
        return jsonify({'message': 'Sent'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@hr_bp.route('/api/hr/messages/<int:student_id>/read', methods=['POST'])
@require_hr_auth
def hr_mark_read(student_id):
    try:
        hr = _get_hr_id_for_session()
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404

        hr_id = hr['id']
        assigned = db.execute_query(
            "SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?",
            (student_id, hr_id),
            fetch_one=True
        )
        if not assigned:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404

        is_true = get_bool_literal(True)
        is_false = get_bool_literal(False)
        db.execute_query(
            f"""UPDATE hr_student_messages
                SET is_read = {is_true}, read_at = ?
                WHERE hr_id = ? AND student_id = ? AND sender_role = 'student' AND is_read = {is_false}""",
            (datetime.now(), hr_id, student_id)
        )
        return jsonify({'message': 'Marked read'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@hr_bp.route('/hr/messages')
@require_hr_auth
def hr_messages_page():
    return render_template('hr/messages.html')

@hr_bp.route('/api/hr/students', methods=['GET'])
@require_hr_auth
def get_students():
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Get assigned students with domains from junction table
        agg_func = get_agg_func()
        students = db.execute_query(
            f'''SELECT s.*, u.email,
                   {agg_func} as domain_names
               FROM students s
               LEFT JOIN users u ON s.user_id = u.id
               LEFT JOIN student_domains sd ON s.id = sd.student_id
               LEFT JOIN domains d ON sd.domain_id = d.id
               WHERE s.assigned_hr_id = ? AND s.account_status = 'active'
               GROUP BY s.id, u.email
               ORDER BY s.full_name''',
            (hr_id,),
            fetch_all=True
        )
        
        # Parse JSON fields and get recruitment status + domain IDs
        result = []
        for student in students:
            student_dict = dict(student)
            student_dict['education_details'] = json.loads(student['education_details']) if student['education_details'] else []
            student_dict['skills'] = json.loads(student['skills']) if student['skills'] else []
            student_dict['projects'] = json.loads(student['projects']) if student['projects'] else []
            student_dict['domain_name'] = student_dict.get('domain_names') or 'No Domain'
            
            # Get domain IDs for filtering
            domain_rows = db.execute_query(
                'SELECT domain_id FROM student_domains WHERE student_id = ?',
                (student['id'],),
                fetch_all=True
            )
            student_dict['domain_ids'] = [r['domain_id'] for r in domain_rows] if domain_rows else []
            
            # Get recruitment status
            status = db.execute_query(
                'SELECT status, notes FROM recruitment_status WHERE student_id = ? AND hr_id = ?',
                (student['id'], hr_id),
                fetch_one=True
            )
            student_dict['recruitment_status'] = status['status'] if status else 'viewed'
            student_dict['recruitment_notes'] = status['notes'] if status else ''
            
            result.append(student_dict)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>', methods=['GET'])
@require_hr_auth
def get_student(student_id):
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Get student (only if assigned to this HR)
        agg_fn = get_agg_func()
        student = db.execute_query(
            f'''SELECT s.*, 
               (SELECT {agg_fn} FROM student_domains sd 
                LEFT JOIN domains d ON sd.domain_id = d.id 
                WHERE sd.student_id = s.id) as domain_name,
               u.email 
               FROM students s
               LEFT JOIN users u ON s.user_id = u.id
               WHERE s.id = ? AND s.assigned_hr_id = ? AND s.account_status = 'active' ''',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Get active certificate
        is_active_val = get_bool_literal(True)
        certificate = db.execute_query(
            f'''SELECT * FROM certificates 
               WHERE student_id = ? AND expiry_date > ? AND is_active = {is_active_val}
               ORDER BY issue_date DESC LIMIT 1''',
            (student_id, datetime.now()),
            fetch_one=True
        )
        
        student_dict = dict(student)
        student_dict['education_details'] = json.loads(student['education_details']) if student['education_details'] else []
        student_dict['skills'] = json.loads(student['skills']) if student['skills'] else []
        student_dict['projects'] = json.loads(student['projects']) if student['projects'] else []
        student_dict['certificate'] = dict(certificate) if certificate else None
        
        return jsonify(student_dict), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/students/filter', methods=['GET'])
@require_hr_auth
def filter_students():
    try:
        user_id = session['user_id']
        domain_id = request.args.get('domain_id')
        skills_filter = request.args.get('skills', '')
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Build query
        agg_fn = get_agg_func()
        query = f'''SELECT s.*, 
                   (SELECT {agg_fn} FROM student_domains sd 
                    LEFT JOIN domains d ON sd.domain_id = d.id 
                    WHERE sd.student_id = s.id) as domain_name,
                   u.email 
                   FROM students s
                   LEFT JOIN users u ON s.user_id = u.id
               WHERE s.assigned_hr_id = ? AND s.account_status = 'active' '''
        params = [hr_id]
        
        if domain_id:
            query += ' AND EXISTS (SELECT 1 FROM student_domains sd2 WHERE sd2.student_id = s.id AND sd2.domain_id = ?)'
            params.append(domain_id)
        
        if skills_filter:
            query += ' AND s.skills LIKE ?'
            params.append(f'%{skills_filter}%')
        
        query += ' ORDER BY s.full_name'
        
        students = db.execute_query(query, tuple(params), fetch_all=True)
        
        # Parse JSON fields
        result = []
        for student in students:
            student_dict = dict(student)
            student_dict['education_details'] = json.loads(student['education_details']) if student['education_details'] else []
            student_dict['skills'] = json.loads(student['skills']) if student['skills'] else []
            student_dict['projects'] = json.loads(student['projects']) if student['projects'] else []
            result.append(student_dict)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/resume/download', methods=['GET'])
@require_hr_auth
def download_student_resume(student_id):
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Get student (verify it's assigned to this HR)
        student = db.execute_query(
            'SELECT resume, full_name, wapl_id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        if not student['resume']:
            return jsonify({'error': 'Student has not uploaded a resume'}), 404
        
        # Build full path to resume file
        resume_path = os.path.join('uploads', student['resume'])
        
        if not os.path.exists(resume_path):
            return jsonify({'error': 'Resume file not found'}), 404
        
        # Get file extension
        file_ext = os.path.splitext(student['resume'])[1]
        return send_file(resume_path, as_attachment=True, download_name=f"{student['wapl_id']}_{student['full_name']}_resume{file_ext}")
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/status', methods=['GET'])
@require_hr_auth
def get_student_recruitment_status(student_id):
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            'SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Get recruitment status
        status = db.execute_query(
            '''SELECT * FROM recruitment_status 
               WHERE student_id = ? AND hr_id = ?''',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if status:
            return jsonify(dict(status)), 200
        else:
            return jsonify({'status': 'viewed', 'notes': ''}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/status', methods=['POST'])
@require_hr_auth
def update_student_recruitment_status(student_id):
    try:
        user_id = session['user_id']
        data = request.get_json()
        
        # Validate input
        status = sanitize_input(data.get('status', ''))
        notes = sanitize_input(data.get('notes', ''))
        
        valid_statuses = ['viewed', 'shortlisted', 'interview_scheduled', 'selected', 'rejected']
        if status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            'SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Check if status record exists
        existing = db.execute_query(
            'SELECT id FROM recruitment_status WHERE student_id = ? AND hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if existing:
            # Update existing record
            db.execute_query(
                '''UPDATE recruitment_status 
                   SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE student_id = ? AND hr_id = ?''',
                (status, notes, student_id, hr_id)
            )
        else:
            # Create new record
            db.execute_query(
                '''INSERT INTO recruitment_status (student_id, hr_id, status, notes)
                   VALUES (?, ?, ?, ?)''',
                (student_id, hr_id, status, notes)
            )
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            hr_details = db.execute_query('SELECT full_name, company_name FROM hrs WHERE id = ?', (hr_id,), fetch_one=True)
            if student_info and hr_details:
                send_student_recruitment_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], status,
                    hr_details['full_name'], hr_details['company_name'], notes
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        log_activity(f'Recruitment status updated to {status}', 'recruitment', target_type='student', target_id=student_id, details=f'Notes: {notes}')

        return jsonify({'message': 'Status updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/shortlist', methods=['POST'])
@require_hr_auth
def shortlist_student(student_id):
    """Shortlist a student"""
    try:
        user_id = session['user_id']
        data = request.get_json()
        notes = sanitize_input(data.get('notes', ''))
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            'SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Update or create recruitment status
        existing = db.execute_query(
            'SELECT id FROM recruitment_status WHERE student_id = ? AND hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if existing:
            db.execute_query(
                '''UPDATE recruitment_status 
                   SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE student_id = ? AND hr_id = ?''',
                (
'shortlisted', notes, student_id, hr_id)
            )
        else:
            db.execute_query(
                '''INSERT INTO recruitment_status (student_id, hr_id, status, notes)
                   VALUES (?, ?, ?, ?)''',
                (student_id, hr_id, 'shortlisted', notes)
            )
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            hr_details = db.execute_query('SELECT full_name, company_name FROM hrs WHERE id = ?', (hr_id,), fetch_one=True)
            if student_info and hr_details:
                send_student_recruitment_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], 'shortlisted',
                    hr_details['full_name'], hr_details['company_name'], notes
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        log_activity('Student shortlisted', 'recruitment', target_type='student', target_id=student_id, details=f'Notes: {notes}')

        print(f"✅ Student {student_id} shortlisted by HR {hr_id}")
        return jsonify({'message': 'Student shortlisted successfully'}), 200
        
    except Exception as e:
        print(f"❌ Error shortlisting student: {e}")
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/interview', methods=['POST'])
@require_hr_auth
def schedule_interview(student_id):
    """Schedule an interview"""
    try:
        user_id = session['user_id']
        data = request.get_json()
        interview_date = sanitize_input(data.get('interview_date', ''))
        interview_time = sanitize_input(data.get('interview_time', ''))
        interview_location = sanitize_input(data.get('interview_location', ''))
        notes = sanitize_input(data.get('notes', ''))
        
        if not interview_date or not interview_time:
            return jsonify({'error': 'Interview date and time are required'}), 400
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            'SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Update recruitment status with interview details
        interview_details = f"Interview scheduled for {interview_date} at {interview_time}"
        if interview_location:
            interview_details += f" ({interview_location})"
        if notes:
            interview_details += f". Notes: {notes}"
        
        existing = db.execute_query(
            'SELECT id FROM recruitment_status WHERE student_id = ? AND hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if existing:
            db.execute_query(
                '''UPDATE recruitment_status 
                   SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE student_id = ? AND hr_id = ?''',
                ('interview_scheduled', interview_details, student_id, hr_id)
            )
        else:
            db.execute_query(
                '''INSERT INTO recruitment_status (student_id, hr_id, status, notes)
                   VALUES (?, ?, ?, ?)''',
                (student_id, hr_id, 'interview_scheduled', interview_details)
            )
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            hr_details = db.execute_query('SELECT full_name, company_name FROM hrs WHERE id = ?', (hr_id,), fetch_one=True)
            if student_info and hr_details:
                send_student_recruitment_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], 'interview_scheduled',
                    hr_details['full_name'], hr_details['company_name'], interview_details
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        log_activity('Interview scheduled', 'recruitment', target_type='student', target_id=student_id, details=interview_details)

        print(f"✅ Interview scheduled for student {student_id} by HR {hr_id}")
        return jsonify({'message': 'Interview scheduled successfully'}), 200
        
    except Exception as e:
        print(f"❌ Error scheduling interview: {e}")
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/reject', methods=['POST'])
@require_hr_auth
def reject_student(student_id):
    """Reject a student"""
    try:
        user_id = session['user_id']
        data = request.get_json()
        reason = sanitize_input(data.get('reason', ''))
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            'SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Update recruitment status
        rejection_notes = f"Rejected"
        if reason:
            rejection_notes += f": {reason}"
        
        existing = db.execute_query(
            'SELECT id FROM recruitment_status WHERE student_id = ? AND hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if existing:
            db.execute_query(
                '''UPDATE recruitment_status 
                   SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE student_id = ? AND hr_id = ?''',
                ('rejected', rejection_notes, student_id, hr_id)
            )
        else:
            db.execute_query(
                '''INSERT INTO recruitment_status (student_id, hr_id, status, notes)
                   VALUES (?, ?, ?, ?)''',
                (student_id, hr_id, 'rejected', rejection_notes)
            )
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            hr_details = db.execute_query('SELECT full_name, company_name FROM hrs WHERE id = ?', (hr_id,), fetch_one=True)
            if student_info and hr_details:
                send_student_recruitment_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], 'rejected',
                    hr_details['full_name'], hr_details['company_name'], rejection_notes
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        log_activity('Student rejected', 'recruitment', target_type='student', target_id=student_id, details=rejection_notes)

        print(f"❌ Student {student_id} rejected by HR {hr_id}")
        return jsonify({'message': 'Student rejected successfully'}), 200
        
    except Exception as e:
        print(f"❌ Error rejecting student: {e}")
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/student/<int:student_id>/select', methods=['POST'])
@require_hr_auth
def select_student(student_id):
    """Mark student as selected/hired"""
    try:
        user_id = session['user_id']
        data = request.get_json()
        offer_notes = sanitize_input(data.get('offer_notes', ''))
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Verify student is assigned to this HR
        student = db.execute_query(
            'SELECT id FROM students WHERE id = ? AND assigned_hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Update recruitment status
        selection_notes = "Selected for position"
        if offer_notes:
            selection_notes += f". Offer details: {offer_notes}"
        
        existing = db.execute_query(
            'SELECT id FROM recruitment_status WHERE student_id = ? AND hr_id = ?',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if existing:
            db.execute_query(
                '''UPDATE recruitment_status 
                   SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE student_id = ? AND hr_id = ?''',
                ('selected', selection_notes, student_id, hr_id)
            )
        else:
            db.execute_query(
                '''INSERT INTO recruitment_status (student_id, hr_id, status, notes)
                   VALUES (?, ?, ?, ?)''',
                (student_id, hr_id, 'selected', selection_notes)
            )
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            hr_details = db.execute_query('SELECT full_name, company_name FROM hrs WHERE id = ?', (hr_id,), fetch_one=True)
            if student_info and hr_details:
                send_student_recruitment_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], 'selected',
                    hr_details['full_name'], hr_details['company_name'], selection_notes
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        log_activity('Student selected', 'recruitment', target_type='student', target_id=student_id, details=selection_notes)

        print(f"✅ Student {student_id} selected by HR {hr_id}")
        return jsonify({'message': 'Student selected successfully'}), 200
        
    except Exception as e:
        print(f"❌ Error selecting student: {e}")
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/recruitment-summary', methods=['GET'])
@require_hr_auth
def get_recruitment_summary():
    """Get recruitment summary for HR"""
    try:
        user_id = session['user_id']
        
        # Get HR ID
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Get recruitment statistics
        total = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE assigned_hr_id = ? AND account_status = 'active'",
            (hr_id,),
            fetch_one=True
        )
        
        viewed = db.execute_query(
            '''SELECT COUNT(*) as count FROM recruitment_status 
               WHERE hr_id = ? AND status IN ('viewed', 'shortlisted', 'interview_scheduled', 'selected', 'rejected')''',
            (hr_id,),
            fetch_one=True
        )
        
        shortlisted = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE hr_id = ? AND status = 'shortlisted'",
            (hr_id,),
            fetch_one=True
        )
        
        interviews = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE hr_id = ? AND status = 'interview_scheduled'",
            (hr_id,),
            fetch_one=True
        )
        
        selected = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE hr_id = ? AND status = 'selected'",
            (hr_id,),
            fetch_one=True
        )
        
        rejected = db.execute_query(
            "SELECT COUNT(*) as count FROM recruitment_status WHERE hr_id = ? AND status = 'rejected'",
            (hr_id,),
            fetch_one=True
        )
        
        return jsonify({
            'total_assigned': total['count'] if total else 0,
            'total_viewed': viewed['count'] if viewed else 0,
            'total_shortlisted': shortlisted['count'] if shortlisted else 0,
            'total_interviews': interviews['count'] if interviews else 0,
            'total_selected': selected['count'] if selected else 0,
            'total_rejected': rejected['count'] if rejected else 0
        }), 200
        
    except Exception as e:
        print(f"Error getting recruitment summary: {e}")
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/hr/dashboard')
@require_hr_auth
def hr_dashboard():
    from flask import render_template
    return render_template('hr/dashboard.html')

@hr_bp.route('/api/hr/dashboard-stats', methods=['GET'])
@require_hr_auth
def hr_dashboard_stats():
    try:
        user_id = session['user_id']
        
        hr = db.execute_query(
            'SELECT id, full_name, company_name FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Total assigned students
        total = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE assigned_hr_id = ?",
            (hr_id,),
            fetch_one=True
        )
        
        # Active students
        active = db.execute_query(
            "SELECT COUNT(*) as count FROM students WHERE assigned_hr_id = ? AND account_status = 'active'",
            (hr_id,),
            fetch_one=True
        )
        
        # Certified students (students assigned to this HR who have an active certificate)
        is_active_val = get_bool_literal(True)
        certified = db.execute_query(
            f"""SELECT COUNT(DISTINCT c.student_id) as count 
                FROM certificates c
                JOIN students s ON c.student_id = s.id
                WHERE s.assigned_hr_id = ? AND c.is_active = {is_active_val}""",
            (hr_id,),
            fetch_one=True
        )
        
        return jsonify({
            'hr_name': hr['full_name'],
            'company_name': hr['company_name'],
            'total_students': total['count'] if total else 0,
            'active_students': active['count'] if active else 0,
            'certified_students': certified['count'] if certified else 0
        }), 200
        
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/profile', methods=['GET'])
@require_hr_auth
def get_hr_profile():
    try:
        user_id = session['user_id']
        
        hr = db.execute_query(
            '''SELECT h.*, u.email 
               FROM hrs h
               LEFT JOIN users u ON h.user_id = u.id
               WHERE h.user_id = ?''',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        profile = dict(hr)
        return jsonify(profile), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/profile', methods=['PUT'])
@require_hr_auth
def update_hr_profile():
    try:
        user_id = session['user_id']
        data = request.get_json()
        
        # Get HR record
        hr = db.execute_query(
            '''SELECT h.*, u.email FROM hrs h
               LEFT JOIN users u ON h.user_id = u.id
               WHERE h.user_id = ?''',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        
        # Sanitize inputs
        full_name = sanitize_input(data.get('full_name', '')).strip()
        phone = sanitize_input(data.get('phone', '')).strip()
        designation = sanitize_input(data.get('designation', '')).strip()
        company_name = sanitize_input(data.get('company_name', '')).strip()
        company_website = sanitize_input(data.get('company_website', '')).strip()
        address = sanitize_input(data.get('address', '')).strip()
        email = sanitize_input(data.get('email', '')).strip().lower()
        
        if not full_name or not phone or not company_name:
            return jsonify({'error': 'Full name, phone, and company name are required'}), 400
        
        # Validate email uniqueness if changed
        if email and email != hr['email']:
            existing = db.execute_query(
                'SELECT id FROM users WHERE email = ? AND id != ?',
                (email, user_id),
                fetch_one=True
            )
            if existing:
                return jsonify({'error': 'Email already in use by another account'}), 400
        
        # Check if there's already a pending change request
        pending = db.execute_query(
            "SELECT id FROM hr_profile_changes WHERE hr_id = ? AND status = 'pending'",
            (hr_id,),
            fetch_one=True
        )
        if pending:
            return jsonify({'error': 'You already have a pending profile change request. Please wait for admin approval.'}), 400
        
        # Build changes dict (only fields that actually changed)
        changes = {}
        if full_name != (hr['full_name'] or ''):
            changes['full_name'] = full_name
        if phone != (hr['phone'] or ''):
            changes['phone'] = phone
        if designation != (hr['designation'] or ''):
            changes['designation'] = designation
        if company_name != (hr['company_name'] or ''):
            changes['company_name'] = company_name
        if company_website != (hr.get('company_website') or ''):
            changes['company_website'] = company_website
        if address != (hr.get('address') or ''):
            changes['address'] = address
        if email and email != (hr['email'] or ''):
            changes['email'] = email
        
        if not changes:
            return jsonify({'error': 'No changes detected'}), 400
        
        # Save as pending change request for admin approval
        db.execute_query(
            '''INSERT INTO hr_profile_changes (hr_id, user_id, changes, status)
               VALUES (?, ?, ?, 'pending')''',
            (hr_id, user_id, json.dumps(changes))
        )
        
        log_activity('Profile change request submitted', 'hr', target_type='hr', target_id=hr_id, details=f'Changed fields: {", ".join(changes.keys())}')

        return jsonify({'message': 'Profile change request submitted successfully. Awaiting admin approval.', 'pending': True}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/profile/pending', methods=['GET'])
@require_hr_auth
def get_pending_profile_changes():
    """Get pending profile change requests for the current HR"""
    try:
        user_id = session['user_id']
        hr = db.execute_query(
            'SELECT id FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        pending = db.execute_query(
            "SELECT * FROM hr_profile_changes WHERE hr_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
            (hr['id'],),
            fetch_one=True
        )
        
        if pending:
            result = dict(pending)
            result['changes'] = json.loads(result['changes'])
            return jsonify(result), 200
        else:
            return jsonify(None), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/change-password', methods=['POST'])
@require_hr_auth
def hr_change_password():
    """Allow HR to change their own password"""
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

        log_activity('change_password', 'hr', target_type='hr', details='Password changed by HR')

        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        print(f'Error changing HR password: {e}')
        return jsonify({'error': str(e)}), 500


@hr_bp.route("/hr/profile")
@require_hr_auth
def hr_profile():
    from flask import render_template
    return render_template("hr/profile.html")

@hr_bp.route('/hr/students')
@require_hr_auth
def hr_students():
    from flask import render_template
    return render_template('hr/students.html')

@hr_bp.route('/hr/student/<int:student_id>')
@require_hr_auth
def hr_student_detail(student_id):
    from flask import render_template
    return render_template('hr/student_detail.html')

@hr_bp.route('/download/certificate/<string:cert_id>', methods=['GET'])
@require_hr_auth
def download_certificate_hr(cert_id):
    """Download certificate PDF - HR access"""
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
        if not pdf_path:
             return jsonify({'error': 'Certificate file not found'}), 404
             
        # If it's a URL (Supabase), redirect
        if pdf_path.startswith('http'):
            return redirect(pdf_path)
            
        if not os.path.exists(pdf_path):
            return jsonify({'error': 'Certificate file not found'}), 404
        
        return send_file(pdf_path, as_attachment=True, download_name=f"{cert_id}.pdf")
        
    except Exception as e:
        print(f"❌ Error downloading certificate: {e}")
        return jsonify({'error': str(e)}), 500

@hr_bp.route('/api/hr/issue-certificate/<int:student_id>', methods=['POST'])
@require_hr_auth
def issue_certificate(student_id):
    """Issue a custom certificate for a student"""
    try:
        user_id = session['user_id']
        data = request.get_json()
        
        # Get HR ID and details
        hr = db.execute_query(
            'SELECT id, full_name, company_name FROM hrs WHERE user_id = ?',
            (user_id,),
            fetch_one=True
        )
        
        if not hr:
            return jsonify({'error': 'HR profile not found'}), 404
        
        hr_id = hr['id']
        hr_name = hr['full_name']
        
        # Verify student is assigned to this HR
        agg_fn = get_agg_func()
        student = db.execute_query(
            f'''SELECT s.*, 
               (SELECT {agg_fn} FROM student_domains sd 
                LEFT JOIN domains d ON sd.domain_id = d.id 
                WHERE sd.student_id = s.id) as domain_name
               FROM students s
               WHERE s.id = ? AND s.assigned_hr_id = ?''',
            (student_id, hr_id),
            fetch_one=True
        )
        
        if not student:
            return jsonify({'error': 'Student not found or not assigned to you'}), 404
        
        # Validate certificate data
        certificate_text = sanitize_input(data.get('certificate_text', ''))
        if not certificate_text:
            return jsonify({'error': 'Certificate text is required'}), 400
        
        # Deactivate any existing active certificates for this student
        is_active_val = get_bool_literal(True)
        is_inactive_val = get_bool_literal(False)
        db.execute_query(
            f"UPDATE certificates SET is_active = {is_inactive_val} WHERE student_id = ? AND is_active = {is_active_val}",
            (student_id,)
        )
        
        # Generate certificate
        cert_unique_id = generate_certificate_id()
        issue_date = datetime.now()
        expiry_date = issue_date.replace(year=issue_date.year + 1)
        
        # Generate QR code - links to report download
        qr_data = f"{request.host_url}download-report/{cert_unique_id}"
        qr_subfolder = 'uploads/qr_codes'
        qr_filename = f'{cert_unique_id}.png'
        
        # Local path for generation (ensure dir exists)
        local_qr_dir = os.path.join(os.getcwd(), qr_subfolder)
        os.makedirs(local_qr_dir, exist_ok=True)
        local_qr_path = os.path.join(local_qr_dir, qr_filename)
        
        generate_qr_code(qr_data, local_qr_path)
        
        # Upload QR to Storage
        qr_code_path = Storage.upload_local_file(local_qr_path, subfolder='qr_codes')
        
        # Generate PDF certificate with custom text and HR name
        cert_subfolder = 'uploads/certificates'
        cert_filename = f'{cert_unique_id}.pdf'
        
        # Local path for generation
        local_cert_dir = os.path.join(os.getcwd(), cert_subfolder)
        os.makedirs(local_cert_dir, exist_ok=True)
        local_cert_path = os.path.join(local_cert_dir, cert_filename)
        
        generate_certificate_pdf(
            student['full_name'],
            student['wapl_id'],
            student['domain_name'],
            issue_date.strftime('%Y-%m-%d'),
            expiry_date.strftime('%Y-%m-%d'),
            local_qr_path, # Use local path for embedding in PDF
            local_cert_path,
            hr_name=hr_name,
            certificate_text=certificate_text
        )
        
        # Upload Certificate to Storage
        pdf_path = Storage.upload_local_file(local_cert_path, subfolder='certificates')
        
        # Create certificate record
        db.execute_query(
            '''INSERT INTO certificates 
               (student_id, certificate_unique_id, issue_date, expiry_date, qr_code, pdf_path, issued_by_hr_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (
                student_id,
                cert_unique_id,
                issue_date,
                expiry_date,
                qr_code_path, # URL or relative path
                pdf_path,    # URL or relative path
                hr_id
            )
        )
        
        # Update student certificate dates
        db.execute_query(
            '''UPDATE students 
               SET certificate_issued_date = ?, certificate_expiry_date = ?
               WHERE id = ?''',
            (issue_date, expiry_date, student_id)
        )
        
        # Send email notification
        try:
            student_info = get_student_notification_info(student_id)
            if student_info:
                send_student_certificate_email(
                    student_info['email'], student_info['full_name'],
                    student_info['wapl_id'], cert_unique_id, action='issued'
                )
        except Exception as email_err:
            print(f"⚠️ Email notification failed: {email_err}")
        
        log_activity('Certificate issued', 'certificate', target_type='student', target_id=student_id, target_name=student['full_name'], details=f'Certificate ID: {cert_unique_id}, Issued by HR: {hr_name}')

        return jsonify({
            'message': 'Certificate issued successfully',
            'certificate_id': cert_unique_id,
            'pdf_url': f'/uploads/certificates/{cert_unique_id}.pdf'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
