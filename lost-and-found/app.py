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
from flask import session, render_template, request, redirect, url_for, flash
import random
import string
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import re
from dotenv import load_dotenv
import mysql.connector

ADMIN_SECRET = "J7v$9XqBd2!Re4Tp"
def is_valid_college_email(email):
    # Regex to match emails that end with @skasc.ac.in (case-insensitive)
    pattern = r'^[a-zA-Z0-9._%+-]+@skasc\.ac\.in$'
    return bool(re.fullmatch(pattern, email.lower()))

load_dotenv()

print("DB_USER loaded:", os.getenv("DB_USER"))
print("DB_PASSWORD loaded:", os.getenv("DB_PASSWORD"))
print("DB_NAME loaded:", os.getenv("DB_NAME"))

app = Flask(__name__, static_folder="static", template_folder="templates")

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-change-me")
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "lost_found_db"),
    "port": int(os.getenv("DB_PORT", "3306")),
}

print("DB_CONFIG:", DB_CONFIG)

def get_db():
    print(f"Connecting to DB as {DB_CONFIG['user']} at {DB_CONFIG['host']}")
    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["database"],
        port=DB_CONFIG["port"],
        autocommit=False,
    )

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

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
            description_match = is_similar(lost['description'], found['description'])
            photo_match = (lost['photo'] is not None and found['photo'] is not None and lost['photo'] == found['photo'])

            if (title_match and description_match) or photo_match:
                matches.append({"lost": lost, "found": found})

    cur.close()
    cnx.close()

    return matches

@app.route("/")
def index():
    return redirect(url_for("intro"))

@app.route("/intro")
def intro():
    return render_template("intro.html")
@app.route("/home")
def home():
    status = request.args.get("status", "lost")
    search = request.args.get("search", "").strip()  # Fetch search query from URL params
    valid = {"lost", "found", "all"}
    if status not in valid:
        status = "lost"
    try:
        cnx = get_db()
        cur = cnx.cursor(dictionary=True)
        if search:
            # If search term exists, use a LIKE query to filter title or description
            if status == "all":
                cur.execute("""
                    SELECT i.*, u.name AS user_name
                    FROM items i
                    JOIN users u ON u.id = i.user_id
                    WHERE i.title LIKE %s OR i.description LIKE %s
                    ORDER BY i.created_at DESC
                """, (f"%{search}%", f"%{search}%"))
            else:
                cur.execute("""
                    SELECT i.*, u.name AS user_name
                    FROM items i
                    JOIN users u ON u.id = i.user_id
                    WHERE i.status=%s AND (i.title LIKE %s OR i.description LIKE %s)
                    ORDER BY i.created_at DESC
                """, (status, f"%{search}%", f"%{search}%"))
        else:
            if status == "all":
                cur.execute("""
                    SELECT i.*, u.name AS user_name
                    FROM items i
                    JOIN users u ON u.id = i.user_id
                    ORDER BY i.created_at DESC
                """)
            else:
                cur.execute("""
                    SELECT i.*, u.name AS user_name
                    FROM items i
                    JOIN users u ON u.id = i.user_id
                    WHERE i.status=%s
                    ORDER BY i.created_at DESC
                """, (status,))
        items = cur.fetchall()
        cur.close()
        cnx.close()
    except Error as e:
        items = []
        flash(f"Database error: {e}", "danger")

    # If you have a find_matches() function, it can stay here or omitted if unused
    matches = find_matches()

    return render_template("home.html", items=items, status=status, search=search, matches=matches)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'         
app.config['MAIL_PORT'] = 587      
app.config['MAIL_USE_TLS'] = True                   
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'lost.and.found.projectcollege@gmail.com' 
app.config['MAIL_PASSWORD'] = 'llcs qlqx bjws vlqv' 
mail = Mail(app)
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(recipient_email, otp_code):
    msg = Message(subject='Your OTP Code - SKASC Lost & Found',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[recipient_email])
    msg.body = f'Your OTP verification code is: {otp_code}. It will expire in 10 minutes.'
    mail.send(msg)
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp', '')
        stored_otp = session.get('signup_otp')
        expiry = session.get('otp_expires', 0)

        if not stored_otp or datetime.utcnow().timestamp() > expiry:
            flash('OTP expired. Please signup again.', 'danger')
            return redirect(url_for('signup'))

        if user_otp == stored_otp:
            # Save user to DB
            email = session.get('signup_email')
            name = session.get('signup_name')
            password_hash = session.get('signup_password')
            password_plain = session.get('signup_plain_password')
            role = session.get('signup_role', 'user')

            try:
                cnx = get_db()
                cur = cnx.cursor()
                cur.execute('INSERT INTO users (name, email, password_hash, password, role) VALUES (%s, %s, %s, %s, %s)',
            (name, email, password_hash, password_plain, role))

                cnx.commit()
                cur.close()
                cnx.close()
            except Exception as e:
                flash(f'Database error: {e}', 'danger')
                return redirect(url_for('signup'))

            # Cleanup session
            session.pop('signup_otp', None)
            session.pop('signup_email', None)
            session.pop('signup_name', None)
            session.pop('signup_password', None)
            session.pop('signup_plain_password', None)
            session.pop('otp_expires', None)

            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')

def is_valid_college_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@skasc\.ac\.in$'
    return bool(re.fullmatch(pattern, email.lower()))

def is_strong_password(pw):
    if not isinstance(pw, str):
        return False
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return bool(re.fullmatch(pattern, pw))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        admin_code = request.form.get("admin_code","").strip()

        if not is_strong_password(password):
            flash("Password must be at least 8 characters long, contain uppercase and lowercase letters, a digit, and a special character (@$!%*?&).", "danger")
            return render_template("signup.html")
        # Basic validations
        if not name or not email or not password:
            flash("All fields are required except admin access code.", "warning")
            return render_template("signup.html")

        if not is_valid_college_email(email):
            flash("Email must end with @skasc.ac.in", "danger")
            return render_template("signup.html")
    
        # Assign role and validate password based on admin code
        if admin_code == ADMIN_SECRET:
            # Admin signup requires strong password
            if not is_strong_password(password):
                flash("Admin password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.", "danger")
                return render_template("signup.html")
            role = "admin"
        else:
            role = "user"

        try:
            cnx = get_db()
            cur = cnx.cursor(dictionary=True)

            # Check if email already registered
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            if cur.fetchone():
                flash("Email already registered. Please log in.", "warning")
                cur.close()
                cnx.close()
                return redirect(url_for("login"))

            cur.close()
            cnx.close()

        except Error as e:
            flash(f"Database error: {e}", "danger")
            return render_template("signup.html")
    
        # Generate OTP and save all signup info + role in session
        otp = generate_otp()
        session['signup_otp'] = otp
        session['signup_email'] = email
        session['signup_name'] = name
        session['signup_password'] = generate_password_hash(password)
        session['signup_plain_password'] = password 
        session['signup_role'] = role
        session['otp_expires'] = (datetime.utcnow() + timedelta(minutes=10)).timestamp()

        # Send OTP email
        send_otp_email(email, otp)
        flash("OTP sent to your email. Please verify.", "info")
        print(f"Entered admin_code: '{admin_code}'")
        print(f"Expected admin code: '{ADMIN_SECRET}'")
        return redirect(url_for("verify_otp"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        cnx = get_db()
        cur = cnx.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        cnx.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        session['user_id'] = user['id']
        session['user_name'] = user['name']
        session['role'] = user['role']  # <-- Store role here

        # Example redirect based on role
        if user['role'] == 'admin':
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('home'))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/lost", methods=["GET", "POST"])
@login_required
def lost_item():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not title or not description:
            flash("Title and description are required.", "warning")
            return render_template("lost_item.html")
        photo_path = None
        file = request.files.get("photo")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Invalid image type. Allowed: png, jpg, jpeg, gif, webp.", "warning")
                return render_template("lost_item.html")
            filename = secure_filename(file.filename)
            ext = filename.rsplit(".", 1)[1].lower()
            filename = f"{uuid4().hex}.{ext}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)
            photo_path = filename  # store filename only
        try:
            cnx = get_db()
            cur = cnx.cursor()
            cur.execute("""
                INSERT INTO items (title, description, photo, status, user_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (title, description, photo_path, "lost", session["user_id"]))
            cnx.commit()
            cur.close()
            cnx.close()
            flash("Lost item submitted.", "success")
            return redirect(url_for("home", status="lost"))
        except Error as e:
            flash(f"Database error: {e}", "danger")
            return render_template("lost_item.html")
    return render_template("lost_item.html")

@app.route("/found", methods=["GET", "POST"])
@login_required
def found_item():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        found_location = request.form.get("found_location", "").strip()
        if not title or not description:
            flash("Title and description are required.", "warning")
            return render_template("found_item.html")
        photo_path = None
        file = request.files.get("photo")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Invalid image type. Allowed: png, jpg, jpeg, gif, webp.", "warning")
                return render_template("found_item.html")
            filename = secure_filename(file.filename)
            ext = filename.rsplit(".", 1)[1].lower()
            filename = f"{uuid4().hex}.{ext}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)
            photo_path = filename
        try:
            cnx = get_db()
            cur = cnx.cursor()
            cur.execute("""
                INSERT INTO items (title, description, photo, status, user_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (title, description, photo_path, "found", session["user_id"]))
            item_id = cur.lastrowid
            if found_location:
                cur.execute("""
                    INSERT INTO reports (item_id, found_location, reporter_id)
                    VALUES (%s, %s, %s)
                """, (item_id, found_location, session["user_id"]))
            cnx.commit()
            cur.close()
            cnx.close()
            flash("Found item reported.", "success")
            return redirect(url_for("home", status="found"))
        except Error as e:
            flash(f"Database error: {e}", "danger")
            return render_template("found_item.html")
    return render_template("found_item.html")

@app.route("/item/<int:item_id>")
def item_detail(item_id):
    try:
        cnx = get_db()
        cur = cnx.cursor(dictionary=True)
        cur.execute("""
            SELECT i.*, u.name AS user_name
            FROM items i
            JOIN users u ON u.id = i.user_id
            WHERE i.id=%s
        """, (item_id,))
        item = cur.fetchone()
        if not item:
            cur.close()
            cnx.close()
            abort(404)
        cur.execute("""
            SELECT r.*, u.name AS reporter_name
            FROM reports r
            LEFT JOIN users u ON u.id = r.reporter_id
            WHERE r.item_id=%s
            ORDER BY r.created_at DESC
        """, (item_id,))
        reports = cur.fetchall()
        cur.close()
        cnx.close()
    except Error as e:
        flash(f"Database error: {e}", "danger")
        return redirect(url_for("home"))
    return render_template("item_detail.html", item=item, reports=reports)

@app.route("/report/<int:item_id>", methods=["POST"])
@login_required
def report_item(item_id):
    found_location = request.form.get("found_location", "").strip()
    if not found_location:
        flash("Please provide a location or details.", "warning")
        return redirect(url_for("item_detail", item_id=item_id))
    try:
        cnx = get_db()
        cur = cnx.cursor()
        cur.execute("SELECT id FROM items WHERE id=%s", (item_id,))
        exists = cur.fetchone()
        if not exists:
            cur.close()
            cnx.close()
            abort(404)
        cur.execute("""
            INSERT INTO reports (item_id, found_location, reporter_id)
            VALUES (%s, %s, %s)
        """, (item_id, found_location, session["user_id"]))
        cnx.commit()
        cur.close()
        cnx.close()
        flash("Report submitted to the owner.", "success")
    except Error as e:
        flash(f"Database error: {e}", "danger")
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/admin")
@login_required
@admin_required
def admin():
    try:
        cnx = get_db()
        cur = cnx.cursor(dictionary=True)
        cur.execute("""
            SELECT i.*, u.name AS user_name
            FROM items i
            JOIN users u ON u.id = i.user_id
            ORDER BY i.created_at DESC
        """)
        items = cur.fetchall()
        cur.close()
        cnx.close()
    except Error as e:
        items = []
        flash(f"Database error: {e}", "danger")
    return render_template("admin.html", items=items)

@app.route("/admin/delete/<int:item_id>", methods=["POST"])
@login_required
@admin_required
def admin_delete(item_id):
    try:
        cnx = get_db()
        cur = cnx.cursor(dictionary=True)
        cur.execute("SELECT photo FROM items WHERE id=%s", (item_id,))
        row = cur.fetchone()
        if row and row["photo"]:
            path = os.path.join(app.config["UPLOAD_FOLDER"], row["photo"])
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass
        cur.execute("DELETE FROM reports WHERE item_id=%s", (item_id,))
        cur.execute("DELETE FROM items WHERE id=%s", (item_id,))
        cnx.commit()
        cur.close()
        cnx.close()
        flash("Item deleted.", "info")
    except Error as e:
        flash(f"Database error: {e}", "danger")
    return redirect(url_for("admin"))

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
