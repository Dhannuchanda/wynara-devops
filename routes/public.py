from flask import Blueprint, request, jsonify, render_template, send_file, abort, redirect
from datetime import datetime
from database import db, get_agg_func, get_bool_literal
from werkzeug.exceptions import HTTPException
import os

public_bp = Blueprint('public', __name__)


def _get_passed_domain_names(student_id):
    """Get only the domain names where the student passed the exam.
    Falls back to all enrolled domains if no exam results exist."""
    if not student_id:
        return 'N/A'
    passed_val = get_bool_literal(True)
    passed_domains = db.execute_query(f"""
        SELECT DISTINCT d.domain_name
        FROM exam_results er
        JOIN domains d ON er.domain_id = d.id
        WHERE er.student_id = ? AND er.passed = {passed_val}
        ORDER BY d.domain_name
    """, (student_id,), fetch_all=True)
    if passed_domains:
        return ', '.join([pd['domain_name'] for pd in passed_domains])
    # Fallback: all enrolled domains
    all_domains = db.execute_query("""
        SELECT d.domain_name FROM student_domains sd
        JOIN domains d ON sd.domain_id = d.id
        WHERE sd.student_id = ?
        ORDER BY d.domain_name
    """, (student_id,), fetch_all=True)
    return ', '.join([d['domain_name'] for d in all_domains]) if all_domains else 'General Training'


@public_bp.route('/download-report/<cert_id>', methods=['GET'])
def download_report(cert_id):
    """Show certificate/report page accessed via QR code scan"""
    try:
        # Get certificate with student info
        certificate = db.execute_query(
            '''SELECT c.*, s.full_name, s.wapl_id, s.phone, s.profile_pic, u.email
               FROM certificates c
               LEFT JOIN students s ON c.student_id = s.id
               LEFT JOIN users u ON s.user_id = u.id
               WHERE c.certificate_unique_id = ?''',
            (cert_id,),
            fetch_one=True
        )
        
        if not certificate:
            return render_template('report_download.html', 
                                 valid=False, 
                                 message='Certificate not found. Please check the QR code and try again.')
        
        cert_dict = dict(certificate)
        
        # Get only PASSED domain names
        cert_dict['domain_names'] = _get_passed_domain_names(cert_dict.get('student_id'))
        
        # Check if certificate is active
        # Handle bool, int, and string representations from different DB drivers
        raw_active = cert_dict.get('is_active')
        is_active = raw_active in (True, 1, '1', 'true', 'True', 'TRUE')
        if not is_active:
            # Certificate was superseded by a newer one (regenerated)
            # Try to find the latest active certificate for this student
            is_active_val = get_bool_literal(True)
            latest_cert = db.execute_query(
                f'''SELECT certificate_unique_id FROM certificates 
                   WHERE student_id = ? AND is_active = {is_active_val}
                   ORDER BY id DESC LIMIT 1''',
                (cert_dict.get('student_id'),),
                fetch_one=True
            )
            if latest_cert:
                # Redirect to the latest active certificate
                return redirect(f'/download-report/{latest_cert["certificate_unique_id"]}')
            
            # No active certificate exists — show info page without revoked error
            return render_template('report_download.html',
                                 valid=True,
                                 certificate=cert_dict,
                                 has_report=False,
                                 report_url=None,
                                 is_expired=False,
                                 cert_id=cert_id,
                                 is_revoked=True)
        
        # Check expiry
        expiry_date = cert_dict.get('expiry_date')
        if isinstance(expiry_date, str):
            expiry_date = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
        is_expired = expiry_date < datetime.now() if expiry_date else False
        
        # Check if report file exists
        report_file = cert_dict.get('report_file')
        has_report = False
        report_url = None
        
        if report_file:
            if report_file.startswith('http'):
                has_report = True
                report_url = report_file
            else:
                # Check local file exists
                file_path = report_file
                if not file_path.startswith('uploads/') and not file_path.startswith('./uploads/'):
                    file_path = f'uploads/{file_path}'
                
                full_path = os.path.join(os.getcwd(), file_path)
                if os.path.exists(full_path):
                    has_report = True
                    report_url = f'/{file_path}'
                else:
                    # Try alternate paths
                    alt_paths = [
                        os.path.join(os.getcwd(), 'uploads', report_file),
                        os.path.join(os.getcwd(), report_file.replace('uploads/', '')),
                    ]
                    for alt in alt_paths:
                        if os.path.exists(alt):
                            has_report = True
                            report_url = f'/uploads/{os.path.basename(alt)}'
                            break
        
        return render_template('report_download.html',
                             valid=True,
                             certificate=cert_dict,
                             has_report=has_report,
                             report_url=report_url,
                             is_expired=is_expired,
                             cert_id=cert_id)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in download-report: {e}")
        import traceback
        traceback.print_exc()
        return render_template('report_download.html', 
                             valid=False, 
                             message=f'An error occurred. Please try again later.')


@public_bp.route('/download-report/<cert_id>/file', methods=['GET'])
def download_report_file(cert_id):
    """Direct file download for report"""
    try:
        certificate = db.execute_query(
            '''SELECT c.report_file, s.full_name, s.wapl_id
               FROM certificates c
               LEFT JOIN students s ON c.student_id = s.id
               WHERE c.certificate_unique_id = ?''',
            (cert_id,),
            fetch_one=True
        )
        
        if not certificate:
            return jsonify({'error': 'Certificate not found'}), 404
        
        cert_dict = dict(certificate)
        report_file = cert_dict.get('report_file')
        
        if not report_file:
            return jsonify({'error': 'No report file available'}), 404
        
        if report_file.startswith('http'):
            return redirect(report_file)
        
        # Resolve local file path
        if not report_file.startswith('uploads/') and not report_file.startswith('./uploads/'):
            report_file = f'uploads/{report_file}'
        
        file_path = os.path.join(os.getcwd(), report_file)
        if not os.path.exists(file_path):
            alt_paths = [
                os.path.join(os.getcwd(), 'uploads', report_file),
                os.path.join(os.getcwd(), report_file.replace('uploads/', '')),
            ]
            file_path = None
            for alt in alt_paths:
                if os.path.exists(alt):
                    file_path = alt
                    break
            if not file_path:
                return jsonify({'error': 'Report file not found on server'}), 404
        
        student_name = cert_dict.get('full_name', 'student').replace(' ', '_')
        wapl_id = cert_dict.get('wapl_id', '')
        file_ext = os.path.splitext(report_file)[1] or '.pdf'
        download_name = f"{student_name}_{wapl_id}_report{file_ext}"
        
        return send_file(file_path, as_attachment=True, download_name=download_name)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error downloading report file: {e}")
        return jsonify({'error': 'Download failed'}), 500


@public_bp.route('/verify-certificate/<cert_id>', methods=['GET'])
def verify_certificate(cert_id):
    try:
        certificate = db.execute_query(
            '''SELECT c.*, s.full_name, s.wapl_id
               FROM certificates c
               LEFT JOIN students s ON c.student_id = s.id
               WHERE c.certificate_unique_id = ?''',
            (cert_id,),
            fetch_one=True
        )
        
        if not certificate:
            return render_template('verify_certificate.html', 
                                 valid=False, 
                                 message='Certificate not found')
        
        cert_dict = dict(certificate)
        # Get only PASSED domain names
        cert_dict['domain_names'] = _get_passed_domain_names(cert_dict.get('student_id'))
        cert_dict['domain_name'] = cert_dict['domain_names']
        
        # Handle both boolean (PostgreSQL) and integer (SQLite) for is_active
        raw_active = cert_dict['is_active']
        is_active = raw_active in (True, 1, '1', 'true', 'True', 'TRUE')
        
        if not is_active:
            # Redirect to latest active certificate for this student
            is_active_val = get_bool_literal(True)
            latest_cert = db.execute_query(
                f'''SELECT certificate_unique_id FROM certificates 
                   WHERE student_id = ? AND is_active = {is_active_val}
                   ORDER BY id DESC LIMIT 1''',
                (cert_dict.get('student_id'),),
                fetch_one=True
            )
            if latest_cert:
                return redirect(f'/verify-certificate/{latest_cert["certificate_unique_id"]}')
            return render_template('verify_certificate.html',
                                 valid=False,
                                 message='Certificate has been superseded. No active certificate found.')
        
        # Handle datetime parsing
        expiry_date = cert_dict['expiry_date']
        if isinstance(expiry_date, str):
            expiry_date = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
        is_expired = expiry_date < datetime.now() if expiry_date else False
        
        if is_expired:
            return render_template('verify_certificate.html',
                                 valid=False,
                                 message='Certificate has expired',
                                 certificate=cert_dict)
        
        return render_template('verify_certificate.html',
                             valid=True,
                             certificate=cert_dict)
        
    except Exception as e:
        return render_template('verify_certificate.html',
                             valid=False,
                             message=f'Error: {str(e)}')

@public_bp.route('/api/verify-certificate/<cert_id>', methods=['GET'])
def verify_certificate_api(cert_id):
    try:
        certificate = db.execute_query(
            '''SELECT c.*, s.full_name, s.wapl_id
               FROM certificates c
               LEFT JOIN students s ON c.student_id = s.id
               WHERE c.certificate_unique_id = ?''',
            (cert_id,),
            fetch_one=True
        )
        
        if not certificate:
            return jsonify({'valid': False, 'message': 'Certificate not found'}), 404
        
        cert_dict = dict(certificate)
        cert_dict['domain_names'] = _get_passed_domain_names(cert_dict.get('student_id'))
        cert_dict['domain_name'] = cert_dict['domain_names']
        
        # Handle datetime parsing for both PostgreSQL and SQLite
        expiry_date = cert_dict['expiry_date']
        if isinstance(expiry_date, str):
            expiry_date = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
        is_expired = expiry_date < datetime.now() if expiry_date else False
        # Handle both boolean (PostgreSQL) and integer (SQLite) for is_active
        raw_active = cert_dict['is_active']
        is_active = raw_active in (True, 1, '1', 'true', 'True', 'TRUE')
        
        if not is_active:
            # Find latest active cert
            is_active_val = get_bool_literal(True)
            latest_cert = db.execute_query(
                f'''SELECT certificate_unique_id FROM certificates 
                   WHERE student_id = ? AND is_active = {is_active_val}
                   ORDER BY id DESC LIMIT 1''',
                (cert_dict.get('student_id'),),
                fetch_one=True
            )
            return jsonify({
                'valid': False, 
                'message': 'Certificate has been superseded',
                'latest_cert_id': latest_cert['certificate_unique_id'] if latest_cert else None
            }), 301
        
        return jsonify({
            'valid': not is_expired,
            'expired': is_expired,
            'certificate': cert_dict
        }), 200
        
    except Exception as e:
        return jsonify({'valid': False, 'message': str(e)}), 500
