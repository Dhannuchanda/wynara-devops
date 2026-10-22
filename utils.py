import secrets
import string
import qrcode
from io import BytesIO
import os
import socket
import requests as http_requests
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from PIL import Image as PILImage, ImageDraw, ImageFont
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Gmail Configuration - support both naming conventions
GMAIL_EMAIL = os.getenv('GMAIL_USER') or os.getenv('GMAIL_EMAIL', '')
GMAIL_PASSWORD = os.getenv('GMAIL_APP_PASSWORD') or os.getenv('GMAIL_PASSWORD', '')
MAIL_SENDER_NAME = os.getenv('MAIL_SENDER_NAME', 'WAPL System')

# Email delivery mode:
# - "auto": try Resend/Gmail, fall back to console only when credentials are missing in dev
# - "smtp": force SMTP/Resend attempts
# - "console": never send externally; print to server console and return success
EMAIL_DELIVERY_MODE = os.getenv('EMAIL_DELIVERY_MODE', 'auto').strip().lower()

# Resend Configuration (alternative email provider)
RESEND_API_KEY = os.getenv('RESEND_API_KEY', '')
RESEND_FROM_EMAIL = os.getenv('RESEND_FROM_EMAIL', 'onboarding@resend.dev')


# ==================== ACTIVITY LOGGING ====================

def log_activity(action, category, target_type=None, target_id=None, target_name=None, details=None):
    """
    Log user activity for audit trail.
    
    Args:
        action: What was done (e.g., 'Approved student', 'Created HR', 'Logged in')
        category: Category grouping - 'auth', 'student', 'hr', 'admin', 'certificate', 
                  'domain', 'exam', 'recruitment', 'payment', 'settings', 'export'
        target_type: Type of entity affected - 'student', 'hr', 'admin', 'certificate', 
                     'domain', 'exam_schedule', 'exam_result', 'payment', 'setting'
        target_id: ID of the affected entity
        target_name: Display name of the affected entity
        details: Extra details as string (e.g., 'Status changed from pending to active')
    """
    try:
        from flask import session, request
        from database import db
        
        user_id = session.get('user_id')
        user_role = session.get('role', 'unknown')
        user_email = session.get('email', '')
        
        # Get user name based on role
        user_name = ''
        if user_id:
            if user_role == 'admin':
                admin = db.execute_query(
                    "SELECT full_name FROM admins WHERE user_id = ?",
                    (user_id,), fetch_one=True
                )
                user_name = admin['full_name'] if admin else 'Admin'
            elif user_role == 'hr':
                hr = db.execute_query(
                    "SELECT full_name FROM hrs WHERE user_id = ?",
                    (user_id,), fetch_one=True
                )
                user_name = hr['full_name'] if hr else 'HR'
            elif user_role == 'student':
                student = db.execute_query(
                    "SELECT full_name FROM students WHERE user_id = ?",
                    (user_id,), fetch_one=True
                )
                user_name = student['full_name'] if student else 'Student'
        
        ip_address = ''
        try:
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr) or ''
        except Exception:
            pass
        
        # Use IST (UTC+5:30) for created_at so logs show correct Indian time
        from zoneinfo import ZoneInfo
        ist_now = datetime.now(ZoneInfo('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S')
        
        db.execute_query("""
            INSERT INTO activity_logs 
            (user_id, user_role, user_name, user_email, action, category, 
             target_type, target_id, target_name, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, user_role, user_name, user_email, action, category,
            target_type, target_id, target_name, details, ip_address, ist_now
        ))
    except Exception as e:
        print(f"⚠️ Activity log error: {e}")


def generate_otp(length=6):
    """Generate a random OTP"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def generate_wapl_id(domain_ids=None):
    """Generate unique WAPL ID in format WAPL-YEAR-CODE-NNNN
    
    Examples:
      WAPL-2026-CS-0001  (Cyber Security, 1st student)
      WAPL-2026-WD-0042  (Web Development, 42nd student)
      WAPL-2026-AI-0001  (AI, 1st student)
    
    Serial number is per-domain per-year.
    For students with multiple domains, uses the first domain.
    Falls back to 'GEN' code if no domain provided.
    """
    from database import db, is_postgres

    try:
        year = datetime.now().year
        domain_code = 'GEN'  # fallback

        # Look up domain short_code from the first domain
        if domain_ids and len(domain_ids) > 0:
            first_domain_id = domain_ids[0] if isinstance(domain_ids, list) else domain_ids
            domain = db.execute_query(
                "SELECT short_code, domain_name FROM domains WHERE id = ?",
                (first_domain_id,),
                fetch_one=True
            )
            if domain:
                if domain.get('short_code'):
                    domain_code = domain['short_code'].upper()
                else:
                    # Auto-generate from name if short_code not set
                    from database import generate_short_code
                    domain_code = generate_short_code(domain['domain_name'])

        # Find the max serial number for this domain code + year
        pattern = f"WAPL-{year}-{domain_code}-%"
        max_result = db.execute_query(
            "SELECT MAX(wapl_id) as max_id FROM students WHERE wapl_id LIKE ?",
            (pattern,),
            fetch_one=True
        )

        if max_result and max_result['max_id']:
            # Extract the serial number (last 4 digits after the last dash)
            last_part = max_result['max_id'].rsplit('-', 1)[-1]
            try:
                max_number = int(last_part)
            except ValueError:
                max_number = 0
            new_number = max_number + 1
        else:
            new_number = 1

        wapl_id = f"WAPL-{year}-{domain_code}-{new_number:04d}"

        # Verify uniqueness
        existing = db.execute_query(
            "SELECT id FROM students WHERE wapl_id = ?",
            (wapl_id,),
            fetch_one=True
        )
        if existing:
            # Increment until unique
            while existing:
                new_number += 1
                wapl_id = f"WAPL-{year}-{domain_code}-{new_number:04d}"
                existing = db.execute_query(
                    "SELECT id FROM students WHERE wapl_id = ?",
                    (wapl_id,),
                    fetch_one=True
                )

        return wapl_id

    except Exception as e:
        print(f"Error generating WAPL ID: {e}")
        # Fallback - use secrets for uniqueness
        import secrets as _secrets
        year = datetime.now().year
        random_num = _secrets.randbelow(90000) + 10000
        fallback_id = f"WAPL-{year}-GEN-{random_num}"
        # Verify uniqueness of fallback
        try:
            existing = db.execute_query(
                "SELECT id FROM students WHERE wapl_id = ?",
                (fallback_id,),
                fetch_one=True
            )
            if existing:
                random_num = _secrets.randbelow(90000) + 10000
                fallback_id = f"WAPL-{year}-GEN-{random_num}"
        except Exception:
            pass
        return fallback_id


def generate_certificate_id():
    """Generate certificate unique ID: CERT + timestamp + 6-char random string"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_str = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    return f'CERT{timestamp}{random_str}'

def generate_qr_code(data, output_path):
    """Generate QR code and save to file"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)
    return output_path

def generate_certificate_pdf(student_name, wapl_id, domain_name, issue_date, expiry_date, qr_code_path, output_path, hr_name=None, certificate_text=None):
    """Generate certificate by overlaying text on base image"""
    try:
        # Use base certificate image from static folder (tracked by git)
        base_image_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'certificates', 'certificate_wapl_id.jpg')
        
        if not os.path.exists(base_image_path):
            # Fallback to ReportLab if template missing
            return generate_certificate_pdf_reportlab(student_name, wapl_id, domain_name, issue_date, expiry_date, qr_code_path, output_path, hr_name, certificate_text)
        
        # Open base image
        img = PILImage.open(base_image_path).convert("RGB")
        draw = ImageDraw.Draw(img)
        
        w, h = img.size
        cx = w // 2  # Center X
        
        # Define colors
        GOLD = "#8a6a2f"
        BLUE = "#1f2b44"
        BLACK = "black"
        
        # Load fonts - adjust paths if needed
        try:
            name_font = ImageFont.truetype("fonts/PlayfairDisplay-Bold.ttf", 90)
            title_font = ImageFont.truetype("fonts/PlayfairDisplay-Bold.ttf", 54)
            body_font = ImageFont.truetype("fonts/PlayfairDisplay-Bold.ttf", 44)
            small_font = ImageFont.truetype("fonts/PlayfairDisplay-Regular.ttf", 36)
        except:
            # Fallback to default if fonts not found
            name_font = ImageFont.load_default()
            title_font = ImageFont.load_default()
            body_font = ImageFont.load_default()
            small_font = ImageFont.load_default()
        
        # Title text
        draw.text((cx, 395), "This certificate is proudly presented to", GOLD, title_font, anchor="mm")
        
        # Student name (prominent)
        draw.text((cx, 480), student_name.upper(), BLUE, name_font, anchor="mm")
        
        # Body text with wrapping
        if certificate_text:
            body_text = certificate_text
        else:
            body_text = f"This certificate recognizes the candidate's hands-on experience in {domain_name} and successful assessment by WAPL."
        
        # Simple text wrapping
        wrapped_lines = []
        words = body_text.split()
        current_line = ""
        max_width = w - 400
        
        for word in words:
            test_line = current_line + (" " if current_line else "") + word
            bbox = draw.textbbox((0, 0), test_line, font=body_font)
            if bbox[2] <= max_width:
                current_line = test_line
            else:
                if current_line:
                    wrapped_lines.append(current_line)
                current_line = word
        
        if current_line:
            wrapped_lines.append(current_line)
        
        # Draw wrapped body text
        body_y = 580
        for line in wrapped_lines:
            draw.text((cx, body_y), line, GOLD, body_font, anchor="ma")
            body_y += 58  # Line spacing
        
        # Bottom section coordinates
        left_x = 180
        base_y = h - 300
        
        # Issue and expiry dates
        draw.text((left_x, base_y), f"Valid From: {issue_date}", BLACK, small_font)
        draw.text((left_x, base_y + 50), f"Valid Until: {expiry_date}", BLACK, small_font)
        draw.text((left_x, base_y + 100), f"WAPL ID: {wapl_id}", BLACK, small_font)
        
        # HR name (if provided)
        if hr_name:
            draw.text((left_x, base_y + 150), f"Issued by: {hr_name}", BLACK, small_font)
        
        # QR Code
        if os.path.exists(qr_code_path):
            qr_img = PILImage.open(qr_code_path)
            qr_img = qr_img.resize((220, 220))
            img.paste(qr_img, (w - 400, base_y - 80))
        
        # Convert to PDF and save
        rgb_img = img.convert('RGB')
        rgb_img.save(output_path, 'PDF')
        return output_path
    
    except Exception as e:
        print(f"Error generating certificate: {str(e)}")
        # Fallback to ReportLab
        return generate_certificate_pdf_reportlab(student_name, wapl_id, domain_name, issue_date, expiry_date, qr_code_path, output_path, hr_name, certificate_text)


def generate_certificate_pdf_reportlab(student_name, wapl_id, domain_name, issue_date, expiry_date, qr_code_path, output_path, hr_name=None, certificate_text=None):
    """Fallback: Generate professional PDF certificate using ReportLab"""
    # Create custom canvas
    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4
    
    # Draw decorative border
    border_color = colors.HexColor('#1a237e')
    c.setStrokeColor(border_color)
    c.setLineWidth(3)
    c.rect(0.5*cm, 0.5*cm, width - 1*cm, height - 1*cm)
    
    # Draw inner decorative line
    c.setLineWidth(1)
    c.rect(1*cm, 1*cm, width - 2*cm, height - 2*cm)
    
    # Add corner decorative elements
    accent_color = colors.HexColor('#283593')
    c.setFillColor(accent_color)
    corner_size = 15
    c.circle(1.5*cm, height - 1.5*cm, corner_size, fill=1)
    c.circle(width - 1.5*cm, height - 1.5*cm, corner_size, fill=1)
    c.circle(1.5*cm, 1.5*cm, corner_size, fill=1)
    c.circle(width - 1.5*cm, 1.5*cm, corner_size, fill=1)
    
    # Title
    c.setFont("Helvetica-Bold", 32)
    c.setFillColor(colors.HexColor('#1a237e'))
    c.drawCentredString(width/2, height - 3*cm, "CERTIFICATE OF REGISTRATION")
    
    # Subtitle line
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.HexColor('#424242'))
    c.drawCentredString(width/2, height - 3.7*cm, "WAPL - Student Portfolio and Placement Management System")
    
    # Main text
    c.setFont("Helvetica", 13)
    c.setFillColor(colors.HexColor('#424242'))
    c.drawCentredString(width/2, height - 5.5*cm, "This is to certify that")
    
    # Student name (prominent)
    c.setFont("Helvetica-Bold", 26)
    c.setFillColor(colors.HexColor('#1a237e'))
    c.drawCentredString(width/2, height - 6.8*cm, student_name)
    
    # Details section
    c.setFont("Helvetica", 12)
    c.setFillColor(colors.HexColor('#424242'))
    c.drawCentredString(width/2, height - 7.7*cm, "has successfully registered with WAPL")
    
    # Details table-like layout
    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(colors.HexColor('#283593'))
    c.drawString(2*cm, height - 8.8*cm, "WAPL ID:")
    c.drawString(2*cm, height - 9.5*cm, "Domain:")
    
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.HexColor('#1a237e'))
    c.drawString(4.5*cm, height - 8.8*cm, wapl_id)
    c.drawString(4.5*cm, height - 9.5*cm, domain_name)
    
    # HR Name
    if hr_name:
        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(colors.HexColor('#283593'))
        c.drawString(2*cm, height - 10.2*cm, "Issued by:")
        
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.HexColor('#1a237e'))
        c.drawString(4.5*cm, height - 10.2*cm, hr_name)
    
    # Validity dates
    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(colors.HexColor('#283593'))
    c.drawString(2*cm, height - 11*cm, "Issue Date:")
    c.drawString(2*cm, height - 11.7*cm, "Expiry Date:")
    
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.HexColor('#1a237e'))
    c.drawString(4.5*cm, height - 11*cm, str(issue_date))
    c.drawString(4.5*cm, height - 11.7*cm, str(expiry_date))
    
    # Certificate text/matter
    if certificate_text:
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor('#424242'))
        # Wrap text
        from reportlab.lib.utils import simpleSplit
        lines = simpleSplit(certificate_text, "Helvetica", 10, width - 4*cm)
        text_y = height - 13*cm
        for line in lines[:4]:  # Max 4 lines
            c.drawString(1.5*cm, text_y, line)
            text_y -= 0.5*cm
    
    # QR Code section
    if os.path.exists(qr_code_path):
        qr_x = width/2 - 1.2*cm
        qr_y = height - 15.5*cm
        c.drawImage(qr_code_path, qr_x, qr_y, width=2.4*cm, height=2.4*cm)
        
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor('#666666'))
        c.drawCentredString(width/2, qr_y - 0.5*cm, "Scan QR Code to Verify")
    
    # Certificate ID footer
    c.setFont("Helvetica", 8)
    c.setFillColor(colors.HexColor('#999999'))
    c.drawCentredString(width/2, 1.2*cm, f"Certificate ID: {wapl_id}")
    
    # Save the canvas
    c.save()
    return output_path

def send_email_simulation(to_email, subject, body):
    """Simulate email sending (console log for now)"""
    print(f"\n{'='*60}")
    print(f"EMAIL SIMULATION")
    print(f"{'='*60}")
    print(f"To: {to_email}")
    print(f"Subject: {subject}")
    print(f"Body:\n{body}")
    print(f"{'='*60}\n")


def _should_use_console_email_mode():
    """Return True when email should be printed to console instead of sent."""
    if EMAIL_DELIVERY_MODE == 'console':
        return True
    if EMAIL_DELIVERY_MODE == 'smtp':
        return False
    # Auto mode: allow console-only fallback during development when creds are missing
    return os.environ.get('FLASK_ENV') != 'production' and (not GMAIL_EMAIL or not GMAIL_PASSWORD)


def send_email_resend(to_email, subject, body, html_body=None):
    """Send email using Resend API"""
    if not RESEND_API_KEY:
        print("📧 Resend API key not configured, skipping...", flush=True)
        return False
    
    try:
        print(f"📧 Sending via Resend API to: {to_email}", flush=True)
        
        payload = {
            "from": f"{MAIL_SENDER_NAME} <{RESEND_FROM_EMAIL}>",
            "to": [to_email],
            "subject": subject,
        }
        
        if html_body:
            payload["html"] = html_body
        else:
            payload["text"] = body
        
        response = http_requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            print(f"✅ Email sent successfully via Resend to {to_email}", flush=True)
            return True
        else:
            print(f"❌ Resend API error: {response.status_code} - {response.text}", flush=True)
            return False
            
    except Exception as e:
        print(f"❌ Resend error: {str(e)}", flush=True)
        return False


def send_email_gmail(to_email, subject, body, html_body=None, attachment_path=None):
    """Send email - tries Resend API first, then Gmail SMTP, then simulation"""

    if _should_use_console_email_mode():
        print("📧 EMAIL_DELIVERY_MODE=console (or dev fallback) - printing OTP email to console only", flush=True)
        send_email_simulation(to_email, subject, body)
        return True
    
    # Try Resend API first if configured
    if RESEND_API_KEY:
        if send_email_resend(to_email, subject, body, html_body):
            return True
        print("📧 Resend failed, trying Gmail SMTP...", flush=True)
    
    try:
        # Debug logging
        print(f"📧 Attempting to send email via Gmail SMTP to: {to_email}", flush=True)
        print(f"📧 GMAIL_EMAIL configured: {'Yes' if GMAIL_EMAIL else 'No'}", flush=True)
        print(f"📧 GMAIL_PASSWORD configured: {'Yes (' + str(len(GMAIL_PASSWORD)) + ' chars)' if GMAIL_PASSWORD else 'No'}", flush=True)
        
        # Verify credentials are set
        if not GMAIL_EMAIL or not GMAIL_PASSWORD:
            print("⚠️ WARNING: Gmail credentials not configured!", flush=True)
            print(f"GMAIL_USER/GMAIL_EMAIL: {GMAIL_EMAIL or 'NOT SET'}")
            print(f"GMAIL_APP_PASSWORD/GMAIL_PASSWORD: {'SET' if GMAIL_PASSWORD else 'NOT SET'}")
            print(f"GMAIL_APP_PASSWORD/GMAIL_PASSWORD: {'SET' if GMAIL_PASSWORD else 'NOT SET'}")
            # Fallback to simulation
            send_email_simulation(to_email, subject, body)
            return True
        
        # Create message
        if attachment_path and os.path.exists(attachment_path):
            message = MIMEMultipart('mixed')
        else:
            message = MIMEMultipart('alternative')
        message['From'] = f"{MAIL_SENDER_NAME} <{GMAIL_EMAIL}>"
        message['To'] = to_email
        message['Subject'] = subject
        
        # Attach plain text body
        message.attach(MIMEText(body, 'plain'))
        
        # Attach HTML body if provided
        if html_body:
            message.attach(MIMEText(html_body, 'html'))
        
        # Attach file if provided
        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename= {os.path.basename(attachment_path)}')
                message.attach(part)
        
        # Send email via Gmail SMTP with timeout
        # Try port 587 with STARTTLS first (more compatible with cloud platforms)
        print(f"📧 Connecting to smtp.gmail.com:587 (STARTTLS)...", flush=True)
        try:
            smtp_server = smtplib.SMTP('smtp.gmail.com', 587, timeout=30)
            smtp_server.ehlo()
            smtp_server.starttls()
            smtp_server.ehlo()
        except Exception as e1:
            print(f"📧 Port 587 failed ({e1}), trying port 465 (SSL)...", flush=True)
            smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=30)
        
        print(f"📧 Connected! Logging in as {GMAIL_EMAIL}...", flush=True)
        smtp_server.login(GMAIL_EMAIL, GMAIL_PASSWORD)
        print(f"📧 Login successful! Sending message...", flush=True)
        smtp_server.send_message(message)
        smtp_server.quit()
        
        print(f"✅ Email sent successfully to {to_email}", flush=True)
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ Gmail authentication failed! Error: {e}", flush=True)
        print("Please check your GMAIL_USER and GMAIL_APP_PASSWORD")
        print("Note: Use Gmail App Password, not your regular password")
        print("Generate at: https://myaccount.google.com/apppasswords")
        if _should_use_console_email_mode():
            send_email_simulation(to_email, subject, body)
            return True
        return False
    
    except socket.timeout:
        print(f"❌ SMTP connection timeout! Gmail SMTP might be blocked.", flush=True)
        if _should_use_console_email_mode():
            send_email_simulation(to_email, subject, body)
            return True
        return False

    except Exception as e:
        print(f"❌ Error sending email: {str(e)}", flush=True)
        import traceback
        traceback.print_exc()
        if _should_use_console_email_mode():
            print(f"Falling back to console simulation...", flush=True)
            send_email_simulation(to_email, subject, body)
            return True
        return False


def debug_gmail_connection(to_email):
    """Debug Gmail connection and return detailed status"""
    status = {
        "success": False,
        "step": "init",
        "error": None,
        "config": {
            "email_set": bool(GMAIL_EMAIL),
            "password_set": bool(GMAIL_PASSWORD),
            "sender_name": MAIL_SENDER_NAME
        }
    }
    
    try:
        # Check config
        if not GMAIL_EMAIL or not GMAIL_PASSWORD:
            status["step"] = "config_check"
            status["error"] = "GMAIL_EMAIL or GMAIL_PASSWORD not set in environment"
            return status
            
        status["step"] = "smtp_connect"
        # Connect to server
        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10)
        
        status["step"] = "login"
        smtp_server.login(GMAIL_EMAIL, GMAIL_PASSWORD)
        
        status["step"] = "prepare_message"
        # Send test message
        message = MIMEMultipart()
        message['From'] = f"{MAIL_SENDER_NAME} <{GMAIL_EMAIL}>"
        message['To'] = to_email
        message['Subject'] = "WAPL Debug Email"
        message.attach(MIMEText("This is a debug email to verify SMTP configuration.", 'plain'))
        
        status["step"] = "send_message"
        smtp_server.send_message(message)
        smtp_server.quit()
        
        status["success"] = True
        status["step"] = "complete"
        return status
        
    except Exception as e:
        status["error"] = str(e)
        import traceback
        status["traceback"] = traceback.format_exc()
        return status


def send_role_otp_email(to_email, otp_code, full_name="User", subject="WAPL OTP Verification", greeting="Hello", intro_line="Your OTP is:", footer_line="If you did not request this OTP, please ignore this email."):
    """Send OTP email with a reusable HTML template"""
    
    # Plain text body
    text_body = f"""
{greeting} {full_name},

{intro_line} {otp_code}

This OTP is valid for 10 minutes.

{footer_line}

Best regards,
WAPL System
"""
    
    # HTML body with styling
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background-color: #f9f9f9;
        }}
        .header {{
            background-color: #1f2b44;
            color: white;
            padding: 20px;
            border-radius: 8px 8px 0 0;
            text-align: center;
        }}
        .header h2 {{
            margin: 0;
            font-size: 24px;
        }}
        .content {{
            padding: 20px;
            background-color: white;
        }}
        .otp-box {{
            background-color: #f0f0f0;
            border: 2px solid #1f2b44;
            padding: 20px;
            text-align: center;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .otp-code {{
            font-size: 36px;
            font-weight: bold;
            color: #1f2b44;
            letter-spacing: 5px;
            font-family: 'Courier New', monospace;
        }}
        .validity {{
            color: #e74c3c;
            font-weight: bold;
            margin-top: 10px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #ddd;
        }}
        .warning {{
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 10px;
            border-radius: 4px;
            margin: 15px 0;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>WAPL Secure Access</h2>
        </div>
        <div class="content">
            <p>Hello <strong>{full_name}</strong>,</p>
            
            <p>Thank you for using WAPL (Student Portfolio and Placement Management System)!</p>
            
            <p>{intro_line}</p>
            
            <div class="otp-box">
                <div class="otp-code">{otp_code}</div>
                <div class="validity">⏱️ Valid for 10 minutes</div>
            </div>
            
            <div class="warning">
                <strong>🔒 Security Notice:</strong> Never share this OTP with anyone. WAPL team will never ask for your OTP.
            </div>
            
            <p>{footer_line}</p>
            
            <p>Need help? Contact our support team.</p>
            
            <p>Best regards,<br><strong>WAPL System</strong></p>
        </div>
        <div class="footer">
            <p>This is an automated email. Please do not reply to this message.</p>
            <p>&copy; 2026 WAPL - Student Portfolio and Placement Management System</p>
        </div>
    </div>
</body>
</html>
"""
    
    return send_email_gmail(to_email, subject, text_body, html_body)


def send_otp_email(to_email, otp_code, full_name="User"):
    """Send registration OTP email."""
    return send_role_otp_email(
        to_email,
        otp_code,
        full_name=full_name,
        subject="WAPL Registration - OTP Verification",
        greeting="Hello",
        intro_line="Your OTP for WAPL Registration is:",
        footer_line="If you did not request this OTP, you can safely ignore this email."
    )


def send_registration_confirmation_email(to_email, full_name, wapl_id):
    """Send registration confirmation email"""
    subject = "WAPL Registration Successful"
    
    text_body = f"""
Hello {full_name},

Congratulations! Your registration with WAPL is complete.

Your WAPL ID: {wapl_id}

Your account is currently pending admin approval. You will receive an email once your account is activated.

Best regards,
WAPL System
"""
    
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background-color: #f9f9f9;
        }}
        .header {{
            background-color: #27ae60;
            color: white;
            padding: 20px;
            border-radius: 8px 8px 0 0;
            text-align: center;
        }}
        .header h2 {{
            margin: 0;
            font-size: 24px;
        }}
        .content {{
            padding: 20px;
            background-color: white;
        }}
        .wapl-id-box {{
            background-color: #ecf0f1;
            border: 2px solid #27ae60;
            padding: 15px;
            text-align: center;
            border-radius: 8px;
            margin: 15px 0;
        }}
        .wapl-id {{
            font-size: 24px;
            font-weight: bold;
            color: #27ae60;
            font-family: 'Courier New', monospace;
        }}
        .info-box {{
            background-color: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 15px 0;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>✅ Registration Successful</h2>
        </div>
        <div class="content">
            <p>Hello <strong>{full_name}</strong>,</p>
            
            <p>Congratulations! Your registration with WAPL is complete. We're excited to have you on board!</p>
            
            <p>Your unique WAPL ID is:</p>
            <div class="wapl-id-box">
                <div class="wapl-id">{wapl_id}</div>
            </div>
            
            <div class="info-box">
                <strong>ℹ️ Next Step:</strong> Your account is currently pending admin approval. You will receive an email notification once your account is activated and ready to use.
            </div>
            
            <p>Thank you for joining WAPL - Student Portfolio and Placement Management System!</p>
            
            <p>Best regards,<br><strong>WAPL System</strong></p>
        </div>
        <div class="footer">
            <p>This is an automated email. Please do not reply to this message.</p>
            <p>&copy; 2026 WAPL</p>
        </div>
    </div>
</body>
</html>
"""
    
    return send_email_gmail(to_email, subject, text_body, html_body)


def send_account_activation_email(to_email, full_name, wapl_id):
    """Send account activation email when admin approves student"""
    subject = "WAPL Account Activated - Ready to Use"
    
    text_body = f"""
Hello {full_name},

Great news! Your WAPL account has been activated by the admin.

Your WAPL ID: {wapl_id}

Your account is now active and ready to use. You can now:
- Access your student dashboard
- View your portfolio
- Participate in recruitment activities
- Download your certificates

You can log in using your registered email and password.

Best regards,
WAPL System
"""
    
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background-color: #f9f9f9;
        }}
        .header {{
            background-color: #27ae60;
            color: white;
            padding: 20px;
            border-radius: 8px 8px 0 0;
            text-align: center;
        }}
        .header h2 {{
            margin: 0;
            font-size: 24px;
        }}
        .content {{
            padding: 20px;
            background-color: white;
        }}
        .success-message {{
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            text-align: center;
            font-size: 18px;
            font-weight: bold;
        }}
        .wapl-id-box {{
            background-color: #ecf0f1;
            border: 2px solid #27ae60;
            padding: 15px;
            text-align: center;
            border-radius: 8px;
            margin: 15px 0;
        }}
        .wapl-id {{
            font-size: 24px;
            font-weight: bold;
            color: #27ae60;
            font-family: 'Courier New', monospace;
        }}
        .features {{
            background-color: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 15px 0;
        }}
        .features ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .features li {{
            margin: 8px 0;
        }}
        .cta-button {{
            display: inline-block;
            background-color: #27ae60;
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>✅ Account Activated</h2>
        </div>
        <div class="content">
            <p>Hello <strong>{full_name}</strong>,</p>
            
            <div class="success-message">
                🎉 Your WAPL account has been activated!
            </div>
            
            <p>Congratulations! The admin has reviewed and approved your registration. Your account is now active and ready to use.</p>
            
            <p>Your WAPL ID:</p>
            <div class="wapl-id-box">
                <div class="wapl-id">{wapl_id}</div>
            </div>
            
            <div class="features">
                <strong>✨ What you can now do:</strong>
                <ul>
                    <li>Access your personalized student dashboard</li>
                    <li>Build and manage your portfolio</li>
                    <li>Participate in recruitment activities</li>
                    <li>Download your certificates</li>
                    <li>Update your profile and skills</li>
                </ul>
            </div>
            
            <p><strong>How to get started:</strong></p>
            <p>Log in to your account using your registered email and password. You'll be directed to your personalized dashboard.</p>
            
            <p>If you have any questions or need assistance, please contact our support team.</p>
            
            <p>Best regards,<br><strong>WAPL System</strong></p>
        </div>
        <div class="footer">
            <p>This is an automated email. Please do not reply to this message.</p>
            <p>&copy; 2026 WAPL - Student Portfolio and Placement Management System</p>
        </div>
    </div>
</body>
</html>
"""
    
    return send_email_gmail(to_email, subject, text_body, html_body)


# ==================== STUDENT NOTIFICATION EMAILS ====================

def get_student_notification_info(student_id):
    """Get student email, name, and WAPL ID for sending notifications"""
    from database import db
    result = db.execute_query(
        '''SELECT s.full_name, s.wapl_id, u.email
           FROM students s
           JOIN users u ON s.user_id = u.id
           WHERE s.id = ?''',
        (student_id,),
        fetch_one=True
    )
    return result


def _send_student_notification(to_email, full_name, wapl_id, subject, heading, heading_color, icon, message_lines, extra_html=''):
    """Generic student notification email with consistent styling"""
    text_body = f"Hello {full_name},\n\n" + "\n".join([line.replace('<strong>', '').replace('</strong>', '') for line in message_lines]) + f"\n\nYour WAPL ID: {wapl_id}\n\nBest regards,\nWAPL System"

    lines_html = ''.join(
        f'<p style="color: #334155; font-size: 15px; line-height: 1.6; margin: 0 0 12px 0;">{line}</p>'
        for line in message_lines
    )

    html_body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background-color:#f1f5f9;">
  <div style="max-width:600px;margin:30px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
    <div style="background:{heading_color};padding:28px 30px;text-align:center;">
      <h2 style="margin:0;color:#fff;font-size:22px;">{icon} {heading}</h2>
    </div>
    <div style="padding:30px;">
      <p style="color:#334155;font-size:15px;margin:0 0 18px 0;">Hello <strong>{full_name}</strong>,</p>
      {lines_html}
      {extra_html}
      <div style="background:#f8fafc;border:2px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center;margin:20px 0;">
        <span style="color:#64748b;font-size:13px;">WAPL ID</span><br>
        <strong style="color:#1e293b;font-size:18px;font-family:'Courier New',monospace;">{wapl_id}</strong>
      </div>
      <p style="color:#334155;font-size:15px;margin:18px 0 0 0;">Best regards,<br><strong>WAPL System</strong></p>
    </div>
    <div style="text-align:center;padding:18px;color:#94a3b8;font-size:11px;border-top:1px solid #e2e8f0;">
      &copy; 2026 WAPL - Student Portfolio and Placement Management System
    </div>
  </div>
</body></html>"""

    return send_email_gmail(to_email, f"WAPL - {subject}", text_body, html_body)


def send_student_status_change_email(to_email, full_name, wapl_id, new_status):
    """Notify student of account status change"""
    status_config = {
        'suspended': {
            'heading': 'Account Suspended',
            'color': '#dc2626',
            'icon': '⚠️',
            'lines': [
                'Your WAPL account has been <strong>suspended</strong> by the administrator.',
                'While suspended, you will not be able to access your dashboard or any platform features.',
                'If you believe this is a mistake, please contact the admin for assistance.'
            ]
        },
        'active': {
            'heading': 'Account Reactivated',
            'color': '#16a34a',
            'icon': '✅',
            'lines': [
                'Great news! Your WAPL account has been <strong>reactivated</strong>.',
                'You can now log in and access all platform features including your dashboard, profile, and certificates.'
            ]
        },
        'revoked': {
            'heading': 'Account Revoked',
            'color': '#dc2626',
            'icon': '🚫',
            'lines': [
                'Your WAPL account has been <strong>revoked</strong> by the administrator.',
                'You will no longer be able to access the platform. Please contact the admin if you have questions.'
            ]
        },
        'pending': {
            'heading': 'Account Set to Pending',
            'color': '#f59e0b',
            'icon': '⏳',
            'lines': [
                'Your WAPL account status has been changed to <strong>pending</strong>.',
                'Your account is awaiting admin review. You will be notified once it is approved.'
            ]
        }
    }

    config = status_config.get(new_status, {
        'heading': f'Account Status: {new_status.title()}',
        'color': '#6366f1',
        'icon': 'ℹ️',
        'lines': [f'Your account status has been updated to <strong>{new_status}</strong>.']
    })

    return _send_student_notification(
        to_email, full_name, wapl_id,
        config['heading'], config['heading'], config['color'], config['icon'], config['lines']
    )


def send_student_hr_assigned_email(to_email, full_name, wapl_id, hr_name, company_name):
    """Notify student when assigned to an HR"""
    extra = f'''<div style="background:#eff6ff;border-left:4px solid #3b82f6;padding:14px;border-radius:0 8px 8px 0;margin:16px 0;">
        <strong style="color:#1e40af;">Assigned HR Details:</strong><br>
        <span style="color:#334155;">👤 {hr_name}<br>🏢 {company_name}</span>
    </div>'''
    return _send_student_notification(
        to_email, full_name, wapl_id,
        'HR Assigned to Your Profile',
        'HR Assigned', '#3b82f6', '🤝',
        [
            f'You have been assigned to <strong>{hr_name}</strong> from <strong>{company_name}</strong>.',
            'The HR professional will be reviewing your profile, resume, and skills for potential opportunities.',
            'Make sure your profile is complete and up to date!'
        ],
        extra
    )


def send_student_hr_unassigned_email(to_email, full_name, wapl_id):
    """Notify student when unassigned from HR"""
    return _send_student_notification(
        to_email, full_name, wapl_id,
        'HR Unassigned from Your Profile',
        'HR Unassigned', '#f59e0b', 'ℹ️',
        [
            'You have been unassigned from your previously assigned HR.',
            'You may be reassigned to a different HR in the future. No action is needed from your side.'
        ]
    )


def send_student_certificate_email(to_email, full_name, wapl_id, cert_id, action='issued'):
    """Notify student when certificate is issued or regenerated"""
    if action == 'regenerated':
        heading = 'Certificate Regenerated'
        icon = '🔄'
        lines = [
            'Your certificate has been <strong>regenerated</strong> with updated information.',
            'The previous certificate has been superseded. Please download the new one from your dashboard.'
        ]
    else:
        heading = 'Certificate Issued'
        icon = '🎓'
        lines = [
            'Congratulations! A <strong>certificate</strong> has been issued to you.',
            'You can now view and download your certificate from your student dashboard.'
        ]

    extra = f'''<div style="background:#f0fdf4;border-left:4px solid #22c55e;padding:14px;border-radius:0 8px 8px 0;margin:16px 0;">
        <strong style="color:#166534;">Certificate ID:</strong>
        <span style="color:#334155;font-family:Courier New,monospace;"> {cert_id}</span>
    </div>'''

    return _send_student_notification(
        to_email, full_name, wapl_id,
        heading, heading, '#16a34a', icon, lines, extra
    )


def send_student_recruitment_email(to_email, full_name, wapl_id, status, hr_name, company_name, notes=''):
    """Notify student of recruitment status updates"""
    status_config = {
        'viewed': ('Profile Viewed', '#6366f1', '👀', 'Your profile has been <strong>viewed</strong>'),
        'shortlisted': ('Shortlisted', '#3b82f6', '⭐', 'You have been <strong>shortlisted</strong>'),
        'interview_scheduled': ('Interview Scheduled', '#8b5cf6', '📅', 'An <strong>interview has been scheduled</strong> for you'),
        'selected': ('Selected', '#16a34a', '🎉', 'Congratulations! You have been <strong>selected</strong>'),
        'rejected': ('Application Update', '#6b7280', '📋', 'Your application status has been updated'),
    }

    heading, color, icon, action_text = status_config.get(
        status,
        (f'Status: {status.replace("_", " ").title()}', '#6366f1', 'ℹ️', f'Your status has been updated to <strong>{status}</strong>')
    )

    lines = [
        f'{action_text} by <strong>{hr_name}</strong> from <strong>{company_name}</strong>.',
    ]

    if status == 'selected':
        lines.append('This is a great achievement! Please check your dashboard for further details.')
    elif status == 'interview_scheduled':
        lines.append('Please check your dashboard for interview details and prepare accordingly.')
    elif status == 'rejected':
        lines.append("Don't be discouraged — there are more opportunities ahead. Keep building your skills!")

    extra = ''
    if notes:
        extra = f'''<div style="background:#f8fafc;border-left:4px solid #94a3b8;padding:14px;border-radius:0 8px 8px 0;margin:16px 0;">
            <strong style="color:#475569;">Notes:</strong>
            <p style="color:#64748b;margin:6px 0 0 0;font-size:14px;">{notes}</p>
        </div>'''

    extra += f'''<div style="background:#eff6ff;border-left:4px solid #3b82f6;padding:14px;border-radius:0 8px 8px 0;margin:16px 0;">
        <strong style="color:#1e40af;">HR:</strong> {hr_name} — {company_name}
    </div>'''

    return _send_student_notification(
        to_email, full_name, wapl_id,
        f'Recruitment Update - {heading}', heading, color, icon, lines, extra
    )


def send_student_domain_update_email(to_email, full_name, wapl_id, domain_names, action='added'):
    """Notify student when domains are added or removed"""
    if action == 'removed':
        heading = 'Domain Removed'
        icon = '📝'
        color = '#f59e0b'
        lines = [
            f'The following domain has been <strong>removed</strong> from your profile: <strong>{domain_names}</strong>.',
            'If you have questions about this change, please contact the administrator.'
        ]
    else:
        heading = 'Domain Added'
        icon = '✨'
        color = '#6366f1'
        lines = [
            f'The following domain(s) have been <strong>added</strong> to your profile: <strong>{domain_names}</strong>.',
            'Your profile has been updated to reflect this change.'
        ]

    return _send_student_notification(
        to_email, full_name, wapl_id,
        heading, heading, color, icon, lines
    )


def sanitize_input(text):
    """Sanitize input to prevent XSS"""
    if not text:
        return ""
    import html
    return html.escape(str(text))

def allowed_file(filename, allowed_extensions):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

from storage import Storage

def save_uploaded_file(file, upload_folder, user_id, file_type):
    """Save uploaded file using Storage abstraction - returns path or URL"""
    if file and file.filename:
        # Extract subfolder from e.g. 'uploads/resumes' -> 'resumes'
        normalized_folder = upload_folder.replace('\\', '/')
        
        if 'uploads/' in normalized_folder:
            parts = normalized_folder.split('uploads/')
            subfolder = parts[1] if len(parts) > 1 else ''
        else:
            subfolder = normalized_folder
            
        return Storage.save_file(file, subfolder=subfolder)
    return None
