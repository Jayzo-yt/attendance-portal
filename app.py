from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import smtplib
import sqlite3
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required, current_user
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy.exc import IntegrityError   # ✅ Fix
from datetime import date

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///club_attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

EMAIL_SENDER = ''
EMAIL_PASSWORD = ''
SMTP_SERVER = ''
SMTP_PORT = 587

# ---------------- Models ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False) 

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    roll_no = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    class_name = db.Column(db.String(50))
    contact = db.Column(db.String(20))
    club_role = db.Column(db.String(50))

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    importance = db.Column(db.String(20))
    urgency = db.Column(db.String(20))
    seriousness = db.Column(db.String(20))


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    method = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)

    member = db.relationship('Member', backref='attendances')
    event = db.relationship('Event', backref='attendances')


class Approval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    taker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default="pending")
    admin_note = db.Column(db.Text)
    member = db.relationship('Member', backref='approvals')
    event = db.relationship('Event', backref='approvals')
    taker = db.relationship('User', foreign_keys=[taker_id])

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='user_audit_logs')

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_audit(user_id, action):
    audit_log = AuditLog(user_id=user_id, action=action)
    db.session.add(audit_log)
    db.session.commit()

def send_email(to, subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

# ---------------- Routes ----------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            log_audit(user.id, f"Logged in as {user.username}")
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit(current_user.id, f"Logged out as {current_user.username}")
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        members_count = Member.query.count()
        pending_approvals = Approval.query.filter_by(status='pending').count()
        events = Event.query.order_by(Event.date_time.desc()).limit(5).all()
        return render_template('admin_dashboard.html', members_count=members_count, pending_approvals=pending_approvals, events=events)
    else:
        events = Event.query.filter(Event.date_time >= datetime.utcnow()).order_by(Event.date_time).all()
        return render_template('taker_dashboard.html', events=events)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(username=email).first()  
        if user:
            
            token = user.username + str(datetime.utcnow().timestamp())
            reset_link = url_for('reset_password', token=token, _external=True)
            send_email(user.username, 'Password Reset Request', f'Click this link to reset your password: {reset_link}')
            flash('Password reset link sent to your email')
        else:
            flash('Email not found')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(username=token.split(str(datetime.utcnow().timestamp()))[0]).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            log_audit(user.id, f"Reset password for {user.username}")
            flash('Password reset successful')
            return redirect(url_for('login'))
        flash('Invalid or expired token')
    return render_template('reset_password.html')

@app.route('/members', methods=['GET', 'POST'])
@login_required
def members():
    if current_user.role != 'admin':
        return 'Access Denied', 403
    if request.method == 'POST':
        action = request.form['action']
        try:
            if action == 'add':
                member = Member(
                    roll_no=request.form['roll_no'],
                    name=request.form['name'],
                    class_name=request.form['class_name'],
                    contact=request.form['contact'],
                    club_role=request.form['club_role']
                )
                db.session.add(member)
                db.session.commit()
                log_audit(current_user.id, f"Added member {member.roll_no}")
                flash('Member added successfully')
            elif action == 'edit':
                member = Member.query.get(request.form['id'])
                if member:
                    member.roll_no = request.form['roll_no']
                    member.name = request.form['name']
                    member.class_name = request.form['class_name']
                    member.contact = request.form['contact']
                    member.club_role = request.form['club_role']
                    db.session.commit()
                    log_audit(current_user.id, f"Edited member {member.roll_no}")
                    flash('Member updated successfully')
                else:
                    flash('Member not found')
            elif action == 'delete':
                member = Member.query.get(request.form['id'])
                if member:
                    db.session.delete(member)
                    db.session.commit()
                    log_audit(current_user.id, f"Deleted member {member.roll_no}")
                    flash('Member deleted successfully')
                else:
                    flash('Member not found')
        except sqlite3.IntegrityError as e:
            db.session.rollback()
            if 'UNIQUE constraint failed: member.roll_no' in str(e):
                flash(f'Roll No "{request.form["roll_no"]}" is already in use. Please use a unique Roll No or edit the existing member.')
            else:
                flash(f'Error: {str(e)}')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}')
    members = Member.query.all()
    return render_template('members.html', members=members)

@app.route('/events', methods=['GET', 'POST'])
@login_required
def events():
    if current_user.role != 'admin':
        return 'Access Denied', 403
    if request.method == 'POST':
        try:
            event = Event(
                name=request.form['name'],
                date_time=datetime.strptime(f"{request.form['date']} {request.form['time']}", '%Y-%m-%d %H:%M'),
                location=request.form['location'],
                type=request.form['type'],
                importance=request.form['importance'],
                urgency=request.form['urgency'],
                seriousness=request.form['seriousness']
            )
            db.session.add(event)
            db.session.commit()
            log_audit(current_user.id, f"Created event {event.name}")
            flash('Event created successfully')
        except ValueError as e:
            db.session.rollback()
            flash('Invalid date or time format')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}')
    events = Event.query.all()
    return render_template('events.html', events=events)



@app.route('/mark_attendance/<int:event_id>', methods=['GET', 'POST'])
@login_required
def mark_attendance(event_id):
    if current_user.role != 'taker':
        return 'Access Denied', 403

    event = Event.query.get_or_404(event_id)
    members = Member.query.all()
    attendees = Attendance.query.filter_by(event_id=event_id).all()

    if request.method == 'POST':
        roll_no = request.form.get('roll_no') or request.form.get('manual_roll_no')
        if not roll_no:
            flash("Roll number is required")
            return redirect(url_for('mark_attendance', event_id=event_id))

        member = Member.query.filter_by(roll_no=roll_no).first()
        if not member:
            if request.form.get('ajax'):
                return jsonify(success=False, message="Invalid Roll No")
            flash("Invalid roll number")
            return redirect(url_for('mark_attendance', event_id=event_id))

        existing = Attendance.query.filter_by(member_id=member.id, event_id=event_id).first()
        if existing:
            if request.form.get('ajax'):
                return jsonify(success=False, message="Attendance already marked")
            flash("Attendance already marked")
            return redirect(url_for('mark_attendance', event_id=event_id))

        # Determine method & status
        method = 'barcode' if request.form.get('roll_no') else 'manual'
        status = 'present' if method == 'barcode' else 'pending'

        # Create attendance
        attendance = Attendance(
            member_id=member.id,
            event_id=event_id,
            date=datetime.utcnow().date(),
            timestamp=datetime.utcnow(),
            method=method,
            status=status
        )
        db.session.add(attendance)

        
        if method == 'manual':
            approval = Approval(member_id=member.id, event_id=event.id, taker_id=current_user.id)
            db.session.add(approval)
            send_email('admin@example.com', 'Manual Attendance Request',
                       f'Request to mark {member.name} ({roll_no}) as present for {event.name}.')
            db.session.commit()
            if request.form.get('ajax'):
                return jsonify(success=True, name=member.name, method=method, status=status,
                               timestamp=attendance.timestamp.strftime('%Y-%m-%d %H:%M:%S'))
            flash("Manual attendance request sent to admin")
        else:
            db.session.commit()
            if request.form.get('ajax'):
                return jsonify(success=True, name=member.name, method=method, status=status,
                               timestamp=attendance.timestamp.strftime('%Y-%m-%d %H:%M:%S'))
            flash("Attendance marked successfully")

        return redirect(url_for('mark_attendance', event_id=event_id))

    return render_template('mark_attendance.html', event=event, members=members, attendees=attendees)


@app.route('/approvals', methods=['GET', 'POST'])
@login_required
def approvals():
    if current_user.role != 'admin':
        return 'Access Denied', 403
    approvals = Approval.query.filter_by(status='pending').all()
    if request.method == 'POST':
        approval_id = request.form['approval_id']
        action = request.form['action']
        approval = Approval.query.get(approval_id)
        if approval:
            attendance = Attendance.query.filter_by(member_id=approval.member_id, event_id=approval.event_id).first()
            if action == 'approve':
                attendance.status = 'present'
                approval.status = 'approved'
                db.session.commit()
                log_audit(current_user.id, f"Approved manual attendance request for {approval.member.roll_no}")
                flash('Attendance approved')
            elif action == 'reject':
                db.session.delete(attendance)
                approval.status = 'rejected'
                approval.admin_note = request.form['admin_note']
                db.session.commit()
                log_audit(current_user.id, f"Rejected manual attendance request for {approval.member.roll_no}")
                flash('Attendance rejected')
    return render_template('approvals.html', approvals=approvals)

@app.route('/statistics')
@login_required
def statistics():
    if current_user.role != 'admin':
        return 'Access Denied', 403
    total_events = Event.query.count()
    stats, low_participation, type_stats = [], [], []
    if total_events > 0:
        members = Member.query.all()
        for member in members:
            attended = Attendance.query.filter_by(member_id=member.id, status='present').count()
            percentage = (attended / total_events) * 100 if total_events else 0
            stats.append({'roll_no': member.roll_no, 'name': member.name, 'attended': attended, 'percentage': round(percentage, 2)})
            if percentage < 50 and attended > 0:
                low_participation.append({'roll_no': member.roll_no, 'name': member.name, 'percentage': round(percentage, 2)})
        
        event_types = Event.query.with_entities(Event.type).distinct().all()
        for et in event_types:
            type_attended = len(set(a.member_id for a in Attendance.query.join(Event).filter(Event.type == et[0], Attendance.status == 'present').all()))
            type_stats.append({'type': et[0], 'attended': type_attended})
    return render_template('statistics.html', stats=stats, low_participation=low_participation, type_stats=type_stats)



@app.route('/export_statistics')
@login_required
def export_statistics():
    if current_user.role != 'admin':
        return 'Access Denied', 403
    format = request.args.get('format')
    total_events = Event.query.count()
    stats = []
    if total_events > 0:
        members = Member.query.all()
        for member in members:
            attended = Attendance.query.filter_by(member_id=member.id, status='present').count()
            percentage = (attended / total_events) * 100 if total_events > 0 else 0
            stats.append([member.roll_no, member.name, member.class_name or 'N/A', member.club_role or 'N/A', attended, f'{round(percentage, 2)}%'])
    if format == 'csv':
        output = io.StringIO()
        output.write('Roll No,Name,Class,Club Role,Events Attended,Attendance %\n')
        for row in stats:
            output.write(','.join(str(cell) for cell in row) + '\n')
        output.seek(0)
        log_audit(current_user.id, "Exported statistics as CSV")
        return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='attendance_stats.csv')
    elif format == 'pdf':
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        table_data = [['Roll No', 'Name', 'Class', 'Club Role', 'Events Attended', 'Attendance %']] + stats
        table = Table(table_data)
        table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), '#007bff'),
                                  ('TEXTCOLOR', (0, 0), (-1, 0), '#ffffff'),
                                  ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                  ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                  ('FONTSIZE', (0, 0), (-1, 0), 14),
                                  ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                  ('BACKGROUND', (0, 1), (-1, -1), '#f8f9fa'),
                                  ('TEXTCOLOR', (0, 1), (-1, -1), '#000000'),
                                  ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                                  ('FONTSIZE', (0, 1), (-1, -1), 12)]))
        doc.build([table])
        log_audit(current_user.id, "Exported statistics as PDF")
        buffer.seek(0)
        return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name='attendance_stats.pdf')
    return 'Invalid format', 400

@app.route('/audit_logs', methods=['GET'])
@login_required
def audit_logs():
    if current_user.role != 'admin':
        return 'Access Denied', 403
    query = AuditLog.query.join(User).options(db.joinedload(AuditLog.user))  # Eager load User
    username = request.args.get('username')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    if username:
        query = query.filter(User.username == username)
    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= start)
        except ValueError:
            flash('Invalid start date')
    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp <= end.replace(hour=23, minute=59, second=59))
        except ValueError:
            flash('Invalid end date')
    logs = query.order_by(AuditLog.timestamp.desc()).all()
    users = User.query.all()
    return render_template('audit_logs.html', logs=logs, users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
       
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=generate_password_hash('adminpass'), role='admin')
            db.session.add(admin)
        if not User.query.filter_by(username='taker').first():
            taker = User(username='taker', password=generate_password_hash('takerpass'), role='taker')
            db.session.add(taker)
        db.session.commit()
    app.run(debug=True)