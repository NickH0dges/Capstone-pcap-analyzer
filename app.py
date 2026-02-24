import os
import sqlite3
import pyshark
from flask import Flask, render_template, request, redirect, send_file, flash
from datetime import datetime
import csv
import asyncio

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.secret_key = "supersecretkey"

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

DB = "database.db"


# ---------------------------
# Database Setup
# ---------------------------
def init_db():
    conn = sqlite3.connect(DB, timeout=30)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port TEXT,
            dst_port TEXT,
            length INTEGER
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            timestamp TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------------------------
# User Model
# ---------------------------
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()

    if user:
        return User(user[0], user[1], user[3])
    return None


# ---------------------------
# Logging
# ---------------------------
def log_action(action):
    conn = sqlite3.connect(DB, timeout=30)
    c = conn.cursor()
    c.execute("INSERT INTO logs (action, timestamp) VALUES (?, ?)",
              (action, datetime.now().isoformat()))
    conn.commit()
    conn.close()


# ---------------------------
# Cleanup Uploaded Files
# ---------------------------
def clear_uploaded_pcaps():
    for filename in os.listdir(UPLOAD_FOLDER):
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")


# ---------------------------
# Parse PCAP
# ---------------------------
def parse_pcap(filepath):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    cap = pyshark.FileCapture(
        filepath,
        keep_packets=False,
        use_json=True,
        include_raw=False
    )

    conn = sqlite3.connect(DB, timeout=30)
    c = conn.cursor()

    for packet in cap:
        try:
            timestamp = packet.sniff_time.isoformat()
            src_ip = packet.ip.src if hasattr(packet, 'ip') else None
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
            protocol = packet.highest_layer
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else None
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else None
            length = int(packet.length)

            c.execute("""
                INSERT INTO packets
                (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length))

        except Exception:
            continue

    conn.commit()
    conn.close()
    cap.close()


# ---------------------------
# AUTH ROUTES
# ---------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):
            login_user(User(user[0], user[1], user[3]))
            log_action(f"Successful login: {username}")
            return redirect("/")
        else:
            log_action(f"Failed login attempt: {username}")
            flash("Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    username = current_user.username

    clear_uploaded_pcaps()
    log_action(f"User logged out and PCAP files cleared: {username}")

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM packets")
    conn.commit()
    conn.close()

    logout_user()
    return redirect("/login")


# ---------------------------
# MAIN ROUTES (PROTECTED)
# ---------------------------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        file = request.files["pcap"]
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        log_action(f"{current_user.username} uploaded PCAP: {file.filename}")
        parse_pcap(filepath)

        return redirect("/dashboard")

    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    filter_ip = request.args.get("ip")
    filter_protocol = request.args.get("protocol")

    conn = sqlite3.connect(DB, timeout=30)
    c = conn.cursor()

    query = "SELECT * FROM packets WHERE 1=1"
    params = []

    if filter_ip:
        query += " AND (src_ip=? OR dst_ip=?)"
        params.extend([filter_ip, filter_ip])

    if filter_protocol:
        query += " AND protocol=?"
        params.append(filter_protocol)

    query += " LIMIT 200"

    c.execute(query, params)
    packets = c.fetchall()
    conn.close()

    return render_template("dashboard.html", packets=packets)


@app.route("/generate_report")
@login_required
def generate_report():
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(REPORT_FOLDER, filename)

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM packets")
    rows = c.fetchall()
    conn.close()

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Timestamp", "Src IP", "Dst IP", "Protocol",
                         "Src Port", "Dst Port", "Length"])
        writer.writerows(rows)

    log_action(f"{current_user.username} generated report")

    return send_file(filepath, as_attachment=True)


@app.route("/timeline")
@login_required
def timeline():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, src_ip, dst_ip, protocol, length
        FROM packets
        ORDER BY timestamp ASC
        LIMIT 500
    """)
    events = c.fetchall()
    conn.close()

    return render_template("timeline.html", events=events)


@app.route("/alerts")
@login_required
def alerts():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    alerts = []

    c.execute("""
        SELECT src_ip, COUNT(*)
        FROM packets
        WHERE protocol='DNS'
        GROUP BY src_ip
        HAVING COUNT(*) > 50
    """)
    for row in c.fetchall():
        alerts.append(f"High DNS activity from {row[0]} ({row[1]} queries)")

    c.execute("""
        SELECT src_ip, SUM(length)
        FROM packets
        GROUP BY src_ip
        HAVING SUM(length) > 1000000
    """)
    for row in c.fetchall():
        alerts.append(f"Large outbound traffic from {row[0]} ({row[1]} bytes)")

    conn.close()

    return render_template("alerts.html", alerts=alerts)


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, threaded=False)