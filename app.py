from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, hashlib, os, random, datetime

app = Flask(__name__)
app.secret_key = 'siem_secret_key_2024'
DB = 'database.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY, timestamp TEXT, source_ip TEXT,
        action TEXT, status TEXT, threat_level TEXT, country TEXT)''')
    salt = 'siem_salt_2024'
    pw = hashlib.sha256(('admin123' + salt).encode()).hexdigest()
    try:
        conn.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", ('admin', pw, salt))
    except: pass
    actions = ['Login Attempt','Port Scan','SQL Injection','Brute Force','File Access','SSH Login']
    statuses = ['Blocked','Allowed','Flagged']
    threats = ['Low','Medium','High','Critical']
    countries = ['US','CN','RU','IN','BR','DE']
    ips = ['192.168.1.1','10.0.0.5','203.0.113.42','198.51.100.7','172.16.0.3']
    for i in range(50):
        ts = (datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0,1440))).strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("INSERT INTO logs (timestamp,source_ip,action,status,threat_level,country) VALUES (?,?,?,?,?,?)",
            (ts, random.choice(ips), random.choice(actions), random.choice(statuses),
             random.choice(threats), random.choice(countries)))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user:
            hashed = hashlib.sha256((password + user['salt']).encode()).hexdigest()
            if hashed == user['password']:
                session['user'] = username
                return redirect(url_for('dashboard'))
        error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    logs = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20").fetchall()
    total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM logs WHERE status='Blocked'").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM logs WHERE threat_level='Critical'").fetchone()[0]
    conn.close()
    return render_template('dashboard.html', logs=logs, total=total, blocked=blocked, critical=critical, user=session['user'])

@app.route('/api/chart-data')
def chart_data():
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    conn = get_db()
    threats = {row['threat_level']: row['cnt'] for row in conn.execute("SELECT threat_level, COUNT(*) as cnt FROM logs GROUP BY threat_level")}
    statuses = {row['status']: row['cnt'] for row in conn.execute("SELECT status, COUNT(*) as cnt FROM logs GROUP BY status")}
    countries = {row['country']: row['cnt'] for row in conn.execute("SELECT country, COUNT(*) as cnt FROM logs GROUP BY country ORDER BY cnt DESC LIMIT 6")}
    conn.close()
    return jsonify({'threats': threats, 'statuses': statuses, 'countries': countries})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)