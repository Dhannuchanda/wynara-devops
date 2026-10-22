"""
Offline Exam System Routes
Handles exam schedule viewing, registration, hall ticket, and result viewing for students.
"""

from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template
from datetime import datetime, timedelta
from database import db, get_bool_literal, is_postgres, get_student_subscription_state
from extensions import limiter

exam_bp = Blueprint('exam', __name__)


# ==================== AUTH DECORATOR ====================


def require_exam_auth(f):
    """Allow access for approved students (exam-eligible) and active students (to view results)"""
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'student':
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Student access required'}), 403
            return redirect(url_for('auth.login_page'))

        student = db.execute_query(
            'SELECT id, account_status, cooldown_until FROM students WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        if not student:
            session.clear()
            return jsonify({'error': 'Student account not found'}), 404

        subscription_state = get_student_subscription_state(student['id'])
        if subscription_state:
            student['account_status'] = subscription_state['account_status']

        if student['account_status'] not in ('approved', 'active'):
            if student['account_status'] == 'expired':
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Your subscription has expired. Please renew your domain payment to continue access.'}), 403
                return redirect(url_for('auth.login_page'))
            if request.path.startswith('/api/'):
                return jsonify({'error': 'You are not eligible for exams'}), 403
            return redirect(url_for('auth.login_page'))

        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


# ==================== PAGE ROUTES ====================


@exam_bp.route('/exam')
@require_exam_auth
def exam_dashboard():
    """Exam dashboard — shows schedules, registrations, results"""
    return render_template('student/exam_dashboard.html')


@exam_bp.route('/exam/hall-ticket/<int:registration_id>')
@require_exam_auth
def hall_ticket(registration_id):
    """Hall ticket page for a registered exam"""
    return render_template('student/hall_ticket.html', registration_id=registration_id)


@exam_bp.route('/exam/result/<int:result_id>')
@require_exam_auth
def exam_result(result_id):
    """Exam result page"""
    return render_template('student/exam_result.html', result_id=result_id)


# ==================== API ROUTES ====================


@exam_bp.route('/api/exam/status', methods=['GET'])
@require_exam_auth
def get_exam_status():
    """Get student's exam status: available schedules, registrations, results"""
    try:
        student = db.execute_query(
            'SELECT id, full_name, account_status, cooldown_until FROM students WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        if not student:
            return jsonify({'error': 'Student not found'}), 404

        # Get ALL student domains
        domains = db.execute_query(
            '''SELECT d.id, d.domain_name FROM student_domains sd
               JOIN domains d ON sd.domain_id = d.id
               WHERE sd.student_id = ?
               ORDER BY d.domain_name''',
            (student['id'],),
            fetch_all=True
        )

        # Get upcoming exam schedules for ALL student domains
        is_active_val = get_bool_literal(True)
        passed_val = get_bool_literal(True)
        today = datetime.now().strftime('%Y-%m-%d')
        available_schedules = []

        # Build per-domain status (which domains are passed, failed with cooldown)
        domain_status = []
        for domain in domains:
            passed = db.execute_query(
                f'SELECT id FROM exam_results WHERE student_id = ? AND domain_id = ? AND passed = {passed_val}',
                (student['id'], domain['id']),
                fetch_one=True
            )
            
            # Check per-domain cooldown
            domain_cd = None
            domain_cd_str = None
            cooldown_record = db.execute_query(
                'SELECT cooldown_until FROM domain_cooldowns WHERE student_id = ? AND domain_id = ?',
                (student['id'], domain['id']),
                fetch_one=True
            )
            if cooldown_record:
                cd = cooldown_record['cooldown_until']
                if isinstance(cd, str):
                    cd = datetime.fromisoformat(cd)
                if datetime.now() < cd:
                    domain_cd = True
                    domain_cd_str = cd.strftime('%Y-%m-%d')
                else:
                    # Expired cooldown — clean up
                    db.execute_query(
                        'DELETE FROM domain_cooldowns WHERE student_id = ? AND domain_id = ?',
                        (student['id'], domain['id'])
                    )
            
            domain_status.append({
                'id': domain['id'],
                'domain_name': domain['domain_name'],
                'passed': passed is not None,
                'cooldown_active': domain_cd is not None,
                'cooldown_until': domain_cd_str
            })

        for domain in domains:
            schedules = db.execute_query(
                f'''SELECT es.*, d.domain_name,
                       (SELECT COUNT(*) FROM exam_registrations WHERE schedule_id = es.id) as registered_count
                   FROM exam_schedules es
                   JOIN domains d ON es.domain_id = d.id
                   WHERE es.domain_id = ? AND es.is_active = {is_active_val}
                     AND es.exam_date >= ?
                   ORDER BY es.exam_date ASC, es.start_time ASC''',
                (domain['id'], today),
                fetch_all=True
            )

            for s in schedules:
                # Check if student is already registered for this schedule
                reg = db.execute_query(
                    'SELECT id, seat_number, status FROM exam_registrations WHERE student_id = ? AND schedule_id = ?',
                    (student['id'], s['id']),
                    fetch_one=True
                )
                s['registration'] = reg

                # Check capacity
                max_s = s['max_students'] or 50
                curr = s['registered_count'] or 0
                s['has_capacity'] = curr < max_s
                s['spots_left'] = max_s - curr

                # Check if this domain has an active cooldown for the student
                ds_match = [ds for ds in domain_status if ds['id'] == s['domain_id']]
                if ds_match and ds_match[0].get('cooldown_active'):
                    s['domain_cooldown'] = True
                    s['domain_cooldown_until'] = ds_match[0]['cooldown_until']
                else:
                    s['domain_cooldown'] = False
                    s['domain_cooldown_until'] = None

                # Serialize dates
                for key in ('exam_date', 'created_at'):
                    if s.get(key) and not isinstance(s[key], str):
                        try:
                            s[key] = s[key].strftime('%Y-%m-%d')
                        except:
                            s[key] = str(s[key])

                available_schedules.append(s)

        # Get student's registrations
        registrations = db.execute_query(
            '''SELECT er.*, es.title, es.exam_date, es.start_time, es.end_time,
                      es.venue, es.venue_address, es.instructions, d.domain_name
               FROM exam_registrations er
               JOIN exam_schedules es ON er.schedule_id = es.id
               JOIN domains d ON es.domain_id = d.id
               WHERE er.student_id = ?
               ORDER BY es.exam_date DESC''',
            (student['id'],),
            fetch_all=True
        )

        for r in registrations:
            for key in ('exam_date', 'registered_at'):
                if r.get(key) and not isinstance(r[key], str):
                    try:
                        r[key] = r[key].strftime('%Y-%m-%d')
                    except:
                        r[key] = str(r[key])

        # Get exam results
        results = db.execute_query(
            '''SELECT er.*, d.domain_name, es.title as schedule_title,
                      es.exam_date, es.venue
               FROM exam_results er
               JOIN domains d ON er.domain_id = d.id
               JOIN exam_schedules es ON er.schedule_id = es.id
               WHERE er.student_id = ?
               ORDER BY er.created_at DESC''',
            (student['id'],),
            fetch_all=True
        )

        for r in results:
            for key in ('exam_date', 'created_at'):
                if r.get(key) and not isinstance(r[key], str):
                    try:
                        r[key] = r[key].strftime('%Y-%m-%d')
                    except:
                        r[key] = str(r[key])
            r['percentage'] = round((r['marks_obtained'] / r['max_marks']) * 100, 1) if r['max_marks'] > 0 else 0

        # Cooldown info
        cooldown = None
        if student.get('cooldown_until'):
            cd = student['cooldown_until']
            if isinstance(cd, str):
                cooldown = cd
            else:
                cooldown = cd.strftime('%Y-%m-%d')

        return jsonify({
            'student': {
                'id': student['id'],
                'full_name': student['full_name'],
                'account_status': student['account_status'],
                'cooldown_until': cooldown
            },
            'domains': domains,
            'domain_status': domain_status,
            'available_schedules': available_schedules,
            'registrations': registrations,
            'results': results
        }), 200

    except Exception as e:
        print(f"Error getting exam status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@exam_bp.route('/api/exam/register', methods=['POST'])
@require_exam_auth
def register_for_exam():
    """Register student for an exam schedule"""
    try:
        data = request.get_json()
        schedule_id = data.get('schedule_id')

        if not schedule_id:
            return jsonify({'error': 'Schedule ID is required'}), 400

        student = db.execute_query(
            'SELECT id, account_status FROM students WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        if not student or student['account_status'] not in ('approved', 'active'):
            return jsonify({'error': 'Only approved/active students can register for exams'}), 403

        # Get schedule
        is_active_val = get_bool_literal(True)
        schedule = db.execute_query(
            f'SELECT * FROM exam_schedules WHERE id = ? AND is_active = {is_active_val}',
            (schedule_id,),
            fetch_one=True
        )

        if not schedule:
            return jsonify({'error': 'Exam schedule not found or inactive'}), 404

        # Check if exam date hasn't passed
        exam_date = schedule['exam_date']
        if isinstance(exam_date, str):
            exam_date = datetime.strptime(exam_date, '%Y-%m-%d').date()
        elif hasattr(exam_date, 'date'):
            exam_date = exam_date.date()

        if exam_date < datetime.now().date():
            return jsonify({'error': 'This exam date has already passed'}), 400

        # Check if already registered
        existing = db.execute_query(
            'SELECT id FROM exam_registrations WHERE student_id = ? AND schedule_id = ?',
            (student['id'], schedule_id),
            fetch_one=True
        )
        if existing:
            return jsonify({'error': 'You are already registered for this exam'}), 400

        # Check capacity
        reg_count = db.execute_query(
            'SELECT COUNT(*) as cnt FROM exam_registrations WHERE schedule_id = ?',
            (schedule_id,),
            fetch_one=True
        )
        max_students = schedule['max_students'] or 50
        if (reg_count['cnt'] or 0) >= max_students:
            return jsonify({'error': 'This exam slot is full'}), 400

        # Check if already passed this domain
        passed_val = get_bool_literal(True)
        already_passed = db.execute_query(
            f'SELECT id FROM exam_results WHERE student_id = ? AND domain_id = ? AND passed = {passed_val}',
            (student['id'], schedule['domain_id']),
            fetch_one=True
        )
        if already_passed:
            return jsonify({'error': 'You have already passed the exam for this domain'}), 400

        # Check per-domain cooldown — block registration if student failed this domain recently
        domain_cooldown = db.execute_query(
            'SELECT cooldown_until FROM domain_cooldowns WHERE student_id = ? AND domain_id = ?',
            (student['id'], schedule['domain_id']),
            fetch_one=True
        )
        if domain_cooldown:
            cd = domain_cooldown['cooldown_until']
            if isinstance(cd, str):
                cd = datetime.fromisoformat(cd)
            if datetime.now() < cd:
                cooldown_date = cd.strftime('%B %d, %Y')
                domain_info = db.execute_query(
                    'SELECT domain_name FROM domains WHERE id = ?',
                    (schedule['domain_id'],),
                    fetch_one=True
                )
                domain_name = domain_info['domain_name'] if domain_info else 'this domain'
                return jsonify({
                    'error': f'You failed the exam for {domain_name}. You can re-apply after {cooldown_date}.',
                    'cooldown_until': cd.strftime('%Y-%m-%d'),
                    'domain_blocked': True
                }), 403
            else:
                # Cooldown expired — clean up the record
                db.execute_query(
                    'DELETE FROM domain_cooldowns WHERE student_id = ? AND domain_id = ?',
                    (student['id'], schedule['domain_id'])
                )

        # Generate seat number
        seat_number = f"S{(reg_count['cnt'] or 0) + 1:03d}"

        # Register
        reg_id = db.execute_query(
            'INSERT INTO exam_registrations (student_id, schedule_id, seat_number) VALUES (?, ?, ?)',
            (student['id'], schedule_id, seat_number)
        )

        return jsonify({
            'message': 'Successfully registered for the exam',
            'registration_id': reg_id,
            'seat_number': seat_number
        }), 201

    except Exception as e:
        print(f"Error registering for exam: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@exam_bp.route('/api/exam/cancel-registration', methods=['POST'])
@require_exam_auth
def cancel_registration():
    """Cancel exam registration (only before exam date)"""
    try:
        data = request.get_json()
        registration_id = data.get('registration_id')

        if not registration_id:
            return jsonify({'error': 'Registration ID is required'}), 400

        student = db.execute_query(
            'SELECT id FROM students WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        # Get registration with schedule info
        reg = db.execute_query(
            '''SELECT er.*, es.exam_date FROM exam_registrations er
               JOIN exam_schedules es ON er.schedule_id = es.id
               WHERE er.id = ? AND er.student_id = ?''',
            (registration_id, student['id']),
            fetch_one=True
        )

        if not reg:
            return jsonify({'error': 'Registration not found'}), 404

        # Check if exam date hasn't passed
        exam_date = reg['exam_date']
        if isinstance(exam_date, str):
            exam_date = datetime.strptime(exam_date, '%Y-%m-%d').date()
        elif hasattr(exam_date, 'date'):
            exam_date = exam_date.date()

        if exam_date <= datetime.now().date():
            return jsonify({'error': 'Cannot cancel registration on or after exam date'}), 400

        # Delete registration
        db.execute_query(
            'DELETE FROM exam_registrations WHERE id = ?',
            (registration_id,)
        )

        return jsonify({'message': 'Registration cancelled successfully'}), 200

    except Exception as e:
        print(f"Error cancelling registration: {e}")
        return jsonify({'error': str(e)}), 500


@exam_bp.route('/api/exam/hall-ticket/<int:registration_id>', methods=['GET'])
@require_exam_auth
def get_hall_ticket(registration_id):
    """Get hall ticket details for a registration"""
    try:
        student = db.execute_query(
            'SELECT id, full_name, wapl_id FROM students WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        reg = db.execute_query(
            '''SELECT er.*, es.title, es.exam_date, es.start_time, es.end_time,
                      es.venue, es.venue_address, es.instructions, d.domain_name
               FROM exam_registrations er
               JOIN exam_schedules es ON er.schedule_id = es.id
               JOIN domains d ON es.domain_id = d.id
               WHERE er.id = ? AND er.student_id = ?''',
            (registration_id, student['id']),
            fetch_one=True
        )

        if not reg:
            return jsonify({'error': 'Registration not found'}), 404

        # Serialize dates
        if reg.get('exam_date') and not isinstance(reg['exam_date'], str):
            reg['exam_date'] = reg['exam_date'].strftime('%Y-%m-%d')
        if reg.get('registered_at') and not isinstance(reg['registered_at'], str):
            try:
                reg['registered_at'] = reg['registered_at'].strftime('%Y-%m-%d %H:%M')
            except:
                reg['registered_at'] = str(reg['registered_at'])

        return jsonify({
            'student': {
                'full_name': student['full_name'],
                'wapl_id': student.get('wapl_id', '')
            },
            'ticket': reg
        }), 200

    except Exception as e:
        print(f"Error getting hall ticket: {e}")
        return jsonify({'error': str(e)}), 500


@exam_bp.route('/api/exam/result/<int:result_id>', methods=['GET'])
@require_exam_auth
def get_exam_result_detail(result_id):
    """Get detailed exam result"""
    try:
        student = db.execute_query(
            'SELECT id, full_name FROM students WHERE user_id = ?',
            (session['user_id'],),
            fetch_one=True
        )

        result = db.execute_query(
            '''SELECT er.*, d.domain_name, es.title as schedule_title,
                      es.exam_date, es.venue
               FROM exam_results er
               JOIN domains d ON er.domain_id = d.id
               JOIN exam_schedules es ON er.schedule_id = es.id
               WHERE er.id = ? AND er.student_id = ?''',
            (result_id, student['id']),
            fetch_one=True
        )

        if not result:
            return jsonify({'error': 'Result not found'}), 404

        for key in ('exam_date', 'created_at'):
            if result.get(key) and not isinstance(result[key], str):
                try:
                    result[key] = result[key].strftime('%Y-%m-%d')
                except:
                    result[key] = str(result[key])

        result['percentage'] = round((result['marks_obtained'] / result['max_marks']) * 100, 1) if result['max_marks'] > 0 else 0

        return jsonify({
            'student_name': student['full_name'],
            'result': result
        }), 200

    except Exception as e:
        print(f"Error getting result: {e}")
        return jsonify({'error': str(e)}), 500
