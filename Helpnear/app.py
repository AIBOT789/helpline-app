from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import os
from flask import session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

DB_PATH = 'helpnear.db'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Ensure user_type column exists
import sqlite3
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("PRAGMA table_info(users)")
columns = [col[1] for col in c.fetchall()]
if 'user_type' not in columns:
    c.execute("ALTER TABLE users ADD COLUMN user_type TEXT DEFAULT 'requester'")
    conn.commit()
conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.secret_key = 'your-secret-key'  # Change to a secure key in production

# Jinja2 filter to display time ago
@app.template_filter('timeago')
def timeago_filter(dt_str):
    if not dt_str:
        return ''
    try:
        # Try parsing as string from SQLite (YYYY-MM-DD HH:MM:SS)
        dt = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
    except Exception:
        try:
            dt = datetime.fromisoformat(dt_str)
        except Exception:
            return dt_str
    now = datetime.now()
    diff = now - dt
    seconds = diff.total_seconds()
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        return f"{int(seconds//60)} minutes ago"
    elif seconds < 86400:
        return f"{int(seconds//3600)} hours ago"
    else:
        return f"{int(seconds//86400)} days ago"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS helpers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        contact TEXT NOT NULL,
        helped_count INTEGER DEFAULT 0,
        earnings REAL DEFAULT 0.0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS help_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        description TEXT,
        price REAL,
        status TEXT,
        category TEXT,
        service_type TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

@app.before_first_request
def setup():
    init_db()

@app.route('/delete_all_requests', methods=['POST'])
def delete_all_requests():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM help_requests')
    conn.commit()
    conn.close()
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Ensure columns exist
    try:
        c.execute('SELECT profile_img, bg_img, description, link FROM users LIMIT 1')
    except sqlite3.OperationalError:
        try:
            c.execute('ALTER TABLE users ADD COLUMN profile_img TEXT')
        except Exception:
            pass
        try:
            c.execute('ALTER TABLE users ADD COLUMN bg_img TEXT')
        except Exception:
            pass
        try:
            c.execute('ALTER TABLE users ADD COLUMN description TEXT')
        except Exception:
            pass
        try:
            c.execute('ALTER TABLE users ADD COLUMN link TEXT')
        except Exception:
            pass
        conn.commit()
    c.execute('SELECT username, profile_img, bg_img, description, link FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if request.method == 'POST':
        # Handle uploads and description
        profile_img = request.files.get('profile_img')
        bg_img = request.files.get('bg_img')
        description = request.form.get('description')
        link = request.form.get('link')
        updates = []
        params = []
        if profile_img and allowed_file(profile_img.filename):
            filename = secure_filename(f"profile_{user_id}_" + profile_img.filename)
            profile_img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            updates.append('profile_img = ?')
            params.append(filename)
        if bg_img and allowed_file(bg_img.filename):
            bgfilename = secure_filename(f"bg_{user_id}_" + bg_img.filename)
            bg_img.save(os.path.join(app.config['UPLOAD_FOLDER'], bgfilename))
            updates.append('bg_img = ?')
            params.append(bgfilename)
        if description is not None:
            updates.append('description = ?')
            params.append(description)
        if link is not None:
            updates.append('link = ?')
            params.append(link)
        if updates:
            params.append(user_id)
            c.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
    c.execute('SELECT username, profile_img, bg_img, description, link FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    # Get this user's published requests
    c = sqlite3.connect(DB_PATH).cursor()
    c.execute('SELECT description, price, category, service_type, status, created_at FROM help_requests WHERE user_id = ?', (user_id,))
    my_requests = c.fetchall()
    conn.close()
    return render_template('profile.html', user=user, my_requests=my_requests)

@app.route('/search_profiles', methods=['GET'])
def search_profiles():
    query = request.args.get('q', '').strip()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, profile_img, description, link FROM users WHERE username LIKE ?", (f"%{query}%",))
    results = c.fetchall()
    conn.close()
    return render_template('search_results.html', query=query, results=results)

@app.route('/profile/<username>')
def public_profile(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, profile_img, bg_img, description, link, user_type FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        return 'User not found', 404
    c.execute('SELECT description, price, category, service_type, status, created_at FROM help_requests WHERE user_id = ?', (user[0],))
    my_requests = c.fetchall()
    conn.close()
    return render_template('profile.html', user=user, my_requests=my_requests, public_view=True)

@app.route('/')
def home():
    if not session.get('username'):
        return redirect(url_for('login'))
    user = session.get('username')
    role = session.get('role')
    user_id = session.get('user_id')
    # Get all open help requests
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT hr.id, u.username, hr.category, hr.service_type, hr.description, hr.price, hr.status, hr.created_at FROM help_requests hr LEFT JOIN users u ON hr.user_id = u.id')
    help_requests = c.fetchall()
    # Get all helpers
    c.execute('SELECT h.id, u.username, h.location, h.contact, h.helped_count, h.earnings FROM helpers h LEFT JOIN users u ON h.user_id = u.id')
    helpers = c.fetchall()
    # If user is a helper, get their earnings
    my_earnings = None
    if role == 'helper' and user_id:
        c.execute('SELECT helped_count, earnings FROM helpers WHERE user_id = ?', (user_id,))
        row = c.fetchone()
        if row:
            my_earnings = {'helped_count': row[0], 'earnings': row[1]}
    # Count user's published requests
    my_requests_count = 0
    if user_id:
        c.execute('SELECT COUNT(*) FROM help_requests WHERE user_id = ?', (user_id,))
        my_requests_count = c.fetchone()[0]
    # Earnings summary (simulate for now)
    earnings_today = 0
    earnings_month = 0
    earnings_lifetime = 0
    paid_by_requesters = 0
    received_as_helper = 0
    if role == 'helper' and user_id:
        c.execute('SELECT SUM(price) FROM help_requests WHERE status = "done" AND user_id = ?', (user_id,))
        earnings_lifetime = c.fetchone()[0] or 0
        earnings_today = earnings_lifetime # Simulate for now
        earnings_month = earnings_lifetime # Simulate for now
        received_as_helper = earnings_lifetime
    if role == 'requester' and user_id:
        c.execute('SELECT SUM(price) FROM help_requests WHERE user_id = ?', (user_id,))
        paid_by_requesters = c.fetchone()[0] or 0
    conn.close()
    return render_template('index.html', user=user, role=role, help_requests=help_requests, helpers=helpers, my_earnings=my_earnings, my_requests_count=my_requests_count, earnings_today=earnings_today, earnings_month=earnings_month, earnings_lifetime=earnings_lifetime, paid_by_requesters=paid_by_requesters, received_as_helper=received_as_helper)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('username'):
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)', (email, username, hashed_password, role))
            conn.commit()
            # Log user in after registration
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            user = c.fetchone()
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = role
            conn.close()
            flash('Registration successful. You are now logged in.', 'success')
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            flash('Email or username already exists.', 'danger')
            return render_template('register.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('username'):
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash, role FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            flash('Login successful.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/register_helper', methods=['GET', 'POST'])
def register_helper():
    if request.method == 'POST':
        name = request.form.get('name')
        location = request.form.get('location')
        contact = request.form.get('contact')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO helpers (name, location, contact) VALUES (?, ?, ?)', (name, location, contact))
        conn.commit()
        conn.close()
        return '<h2>Thank you for registering as a helper!</h2><a href="/">Back to Home</a>'
    return render_template('register_helper.html')

@app.route('/request_help', methods=['POST'])
def request_help():
    description = request.form.get('description')
    price = request.form.get('price')
    category = request.form.get('category')
    user_id = session.get('user_id')
    # Store help request in DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO help_requests (user_id, description, price, category) VALUES (?, ?, ?, ?)', (user_id, description, price, category))
    request_id = c.lastrowid
    conn.commit()
    conn.close()
    return f"""
        <h2>Thank you for submitting your help request!</h2>
        <p>Description: {description}</p>
        <a href='/'>Back to Home</a>
    """

@app.route('/find_helpers', methods=['POST'])
def find_helpers():
    location = request.form.get('location')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Improved: match helpers with similar/nearby locations (case-insensitive partial match)
    c.execute('SELECT name, contact, location FROM helpers WHERE LOWER(location) LIKE ?', (f'%{location.lower()}%',))
    helpers = c.fetchall()
    conn.close()
    if helpers:
        helpers_html = '<ul>' + ''.join([f'<li>{h[0]} (Location: {h[2]}, Contact: {h[1]})</li>' for h in helpers]) + '</ul>'
    else:
        helpers_html = '<p>No helpers found near your location.</p>'
    return f"""
        <h2>Helpers near {location}:</h2>
        {helpers_html}
        <a href='/'>Back to Home</a>
    """

@app.route('/set_status/<int:request_id>/<status>', methods=['POST'])
def set_status(request_id, status):
    # Only helpers can set status
    if session.get('role') != 'helper':
        flash('Only helpers can update status.', 'danger')
        return redirect(url_for('home'))
    if status not in ['open', 'in_progress', 'done']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('home'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE help_requests SET status = ? WHERE id = ?', (status, request_id))
    # If marking as done, increment helped_count and earnings for the helper
    if status == 'done':
        user_id = session.get('user_id')
        if user_id:
            c.execute('UPDATE helpers SET helped_count = helped_count + 1, earnings = earnings + 10 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'Request status updated to {status}.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
