from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb.cursors
import re
import config
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'a4c7e9bdb64e49f9a1ff6a2ab2d71bc1'  # Change this in production!

# MySQL Config
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB

mysql = MySQL(app)

# Email Config (Update with your SMTP settings)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'wahhajsiraj16@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'muai zlli vrhu imsd'  # Replace with your app-specific password
app.config['MAIL_SENDER'] = 'wahhajsiraj16@gmail.com' # Replace with your email

# Token serializer for password reset
serializer = URLSafeTimedSerializer(app.secret_key)

def send_reset_email(email, token):
    msg = MIMEText(f"""
    To reset your password, click the following link:
    {url_for('reset_password_token', token=token, _external=True)}
    
    If you did not request this, please ignore this email.
    The link will expire in 30 minutes.
    """)
    msg['Subject'] = 'Password Reset Request'
    msg['From'] = app.config['MAIL_SENDER']
    msg['To'] = email

    try:
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.sendmail(app.config['MAIL_SENDER'], email, msg.as_string())
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        email = request.form['email']  # Add this
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user:
            flash("Username already exists!", "danger")
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, password, role, email) VALUES (%s, %s, %s, %s)",
        (username, hashed_pw, role, email))
        mysql.connection.commit()
        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password_input):
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'editor':
                return redirect(url_for('editor_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET'])
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            if send_reset_email(email, token):
                flash("A password reset link has been sent to your email.", "success")
            else:
                flash("Failed to send reset email. Please try again.", "danger")
        else:
            flash("Email not found.", "danger")
        return redirect(url_for('login'))
    return redirect(url_for('forgot_password'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=1800)  # 30 minutes expiry
    except (SignatureExpired, BadSignature):
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password_token', token=token))
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return redirect(url_for('reset_password_token', token=token))
        
        hashed_pw = generate_password_hash(password)
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
        mysql.connection.commit()
        flash("Your password has been reset successfully.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    return render_template('dashboard_admin.html')

@app.route('/editor')
def editor_dashboard():
    if session.get('role') != 'editor':
        return redirect(url_for('login'))
    return render_template('dashboard_editor.html')

@app.route('/user')
def user_dashboard():
    if session.get('role') != 'user':
        return redirect(url_for('login'))
    return render_template('dashboard_user.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You’ve been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)