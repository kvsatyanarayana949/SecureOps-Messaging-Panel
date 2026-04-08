import os
import logging
import html
import traceback
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_mysqldb import MySQL
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

# =========================
# APP INIT
# =========================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')

# =========================
# SESSION SECURITY
# =========================
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # True in HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.permanent_session_lifetime = timedelta(minutes=30)

# =========================
# CSRF
# =========================
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']
csrf = CSRFProtect(app)

# =========================
# MYSQL CONFIG
# =========================
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'root')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'test')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# =========================
# RATE LIMIT
# =========================
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100/hour"]
)

# =========================
# LOGGING
# =========================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =========================
# DB HEALTH CHECK
# =========================
def check_db_connection():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return True
    except Exception:
        return False

# =========================
# ERROR HANDLER
# =========================
@app.errorhandler(Exception)
def handle_error(e):
    logger.error(traceback.format_exc())
    return jsonify({"status": "error", "message": "Internal Server Error"}), 500

# =========================
# HELPERS
# =========================
def get_cursor():
    return mysql.connection.cursor()

def admin_required():
    return 'role' in session and session['role'] == 'admin'

# =========================
# HOME
# =========================
@app.route('/')
def home():
    messages = []
    cur = None
    try:
        cur = get_cursor()
        cur.execute("SELECT message FROM messages ORDER BY id DESC LIMIT 50")
        messages = cur.fetchall()
    except Exception:
        logger.error(traceback.format_exc())
    finally:
        if cur:
            cur.close()

    return render_template('index.html', messages=messages)

# =========================
# REGISTER
# =========================
@app.route('/register', methods=['POST'])
@limiter.limit("5/minute")
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({"status": "error", "message": "Invalid input"}), 400

    hashed = generate_password_hash(password)

    cur = None
    try:
        cur = get_cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s,%s)",
            (username, hashed)
        )
        mysql.connection.commit()

        return jsonify({"status": "success"})

    except Exception as e:
        mysql.connection.rollback()
        logger.error(str(e))

        if "Duplicate entry" in str(e):
            return jsonify({"status": "error", "message": "User already exists"}), 400

        return jsonify({"status": "error", "message": "Registration failed"}), 500

    finally:
        if cur:
            cur.close()

# =========================
# LOGIN
# =========================
@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    cur = None
    try:
        cur = get_cursor()
        cur.execute("SELECT * FROM users WHERE username=%s", [username])
        user = cur.fetchone()

        if not user:
            return jsonify({"status": "error", "message": "User not found"})

        if user['is_banned']:
            cur.execute(
                "INSERT INTO logs (event_type, username, ip_address, status) VALUES (%s,%s,%s,%s)",
                ("BANNED_LOGIN", username, request.remote_addr, "blocked")
            )
            mysql.connection.commit()
            return jsonify({"status": "error", "message": "You are banned"})

        if check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            cur.execute(
                "INSERT INTO logs (event_type, username, ip_address, status) VALUES (%s,%s,%s,%s)",
                ("LOGIN_SUCCESS", username, request.remote_addr, "success")
            )
            mysql.connection.commit()

            return jsonify({
                "status": "success",
                "username": user['username'],
                "role": user['role']
            })

        else:
            cur.execute(
                "INSERT INTO logs (event_type, username, ip_address, status) VALUES (%s,%s,%s,%s)",
                ("LOGIN_FAILED", username, request.remote_addr, "fail")
            )
            mysql.connection.commit()

            return jsonify({"status": "error", "message": "Wrong password"})

    except Exception:
        mysql.connection.rollback()
        logger.error(traceback.format_exc())
        return jsonify({"status": "error", "message": "Login failed"}), 500

    finally:
        if cur:
            cur.close()

# =========================
# LOGOUT
# =========================
@app.route('/logout')
def logout():
    session.clear()
    return jsonify({"status": "success"})

# =========================
# SEND MESSAGE
# =========================
@app.route('/submit', methods=['POST'])
@limiter.limit("10/minute")
def submit():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    msg = request.form.get('new_message')

    if not msg or len(msg) > 500:
        return jsonify({"status": "error", "message": "Invalid message"}), 400

    msg = html.escape(msg)

    cur = None
    try:
        cur = get_cursor()
        cur.execute(
            "INSERT INTO messages (message, sender_id) VALUES (%s,%s)",
            (msg, session['user_id'])
        )
        mysql.connection.commit()

        return jsonify({"status": "success", "message": msg})

    except Exception:
        mysql.connection.rollback()
        logger.error(traceback.format_exc())
        return jsonify({"status": "error"}), 500

    finally:
        if cur:
            cur.close()

# =========================
# BAN USER
# =========================
@app.route('/ban_user', methods=['POST'])
def ban_user():
    if not admin_required():
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    username = request.form.get('username')

    cur = None
    try:
        cur = get_cursor()
        cur.execute("UPDATE users SET is_banned=TRUE WHERE username=%s", [username])
        mysql.connection.commit()

        logger.warning(f"User banned: {username}")
        return jsonify({"status": "success"})

    except Exception:
        mysql.connection.rollback()
        logger.error(traceback.format_exc())
        return jsonify({"status": "error"}), 500

    finally:
        if cur:
            cur.close()

# =========================
# ADMIN: USERS
# =========================
@app.route('/users')
def get_users():
    if not admin_required():
        return jsonify([])

    cur = None
    try:
        cur = get_cursor()
        cur.execute("SELECT username, role FROM users")
        users = cur.fetchall()
        return jsonify(users)

    finally:
        if cur:
            cur.close()

# =========================
# ADMIN: LOGS
# =========================
@app.route('/logs')
def get_logs():
    if not admin_required():
        return jsonify([])

    cur = None
    try:
        cur = get_cursor()
        cur.execute("SELECT event_type, username FROM logs ORDER BY id DESC LIMIT 50")
        logs = cur.fetchall()
        return jsonify(logs)

    finally:
        if cur:
            cur.close()

# =========================
# RUN
# =========================
if __name__ == '__main__':
    if not check_db_connection():
        print("Database connection failed. Check MySQL.")
    else:
        print("Database connected successfully")

    app.run(debug=True)
