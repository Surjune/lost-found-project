from dotenv import load_dotenv
import os
import difflib
from uuid import uuid4
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, send_from_directory
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import mysql.connector
from mysql.connector import Error
from flask_mail import Mail, Message
import random
import string
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse

# Admin signup secret
ADMIN_SECRET = "J7v$9XqBd2!Re4Tp"

def is_valid_college_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@skasc\.ac\.in$'
    return bool(re.fullmatch(pattern, email.lower()))

def is_strong_password(pw):
    if not isinstance(pw, str):
        return False
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return bool(re.fullmatch(pattern, pw))

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

load_dotenv()

# Flask app
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-change-me")
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# DATABASE CONFIG (Render + Railway MySQL)
db_url = os.getenv("DATABASE_URL")
if db_url:
    result = urlparse(db_url)
    DB_CONFIG = {
        "host": result.hostname,
        "user": result.username,
        "password": result.password,
        "database": result.path[1:],
        "port": result.port
    }
else:
    DB_CONFIG = {
        "host": os.getenv("DB_HOST", "127.0.0.1"),
        "user": os.getenv("DB_USER", "root"),
        "password": os.getenv("DB_PASSWORD", ""),
        "database": os.getenv("DB_NAME", "lost_found_db"),
        "port": int(os.getenv("DB_PORT", "3306")),
    }

print("DB_CONFIG:", DB_CONFIG)

def get_db():
    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["database"],
        port=DB_CONFIG["port"],
        autocommit=False
    )

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Match finder
def is_similar(text1, text2, threshold=0.6):
    if not text1 or not text2:
        return False
    ratio = difflib.SequenceMatcher(None, text1.lower(), text2.lower()).ratio()
    return ratio >= threshold

def find_matches():
    cnx = get_db()
    cur = cnx.cursor(dictionary=True)
    cur.execute("SELECT * FROM items WHERE status='lost'")
    lost_items = cur.fetchall()
    cur.execute("SELECT * FROM items WHERE status='found'")
    found_items = cur.fetchall()
    matches = []
    for lost in lost_items:
        for found in found_items:
            title_match = is_similar(lost['title'], found['title'])
            desc_match = is_similar(lost['description'], found['description'])
            photo_match = lost.get('photo') and lost['photo'] == found.get('photo')
            if (title_match and desc_match) or photo_match:
                matches.append({"lost": lost, "found": found})
    cur.close()
    cnx.close()
    return matches

# Flask-Mail setup
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD")
)
mail = Mail(app)

def send_otp_email(recipient_email, otp_code):
    msg = Message(
        subject='Your OTP Code - SKASC Lost & Found',
        sender=app.config['MAIL_USERNAME'],
        recipients=[recipient_email]
    )
    msg.body = f'Your OTP verification code is: {otp_code}. It expires in 10 minutes.'
    mail.send(msg)

# Routes
@app.route("/")
def index():
    return redirect(url_for("intro"))

@app.route("/intro")
def intro():
    return render_template("intro.html")

# ... include all other routes here exactly as in your original code ...
# signup, login, logout, lost_item, found_item, item_detail, report_item, admin, admin_delete

# Run server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
