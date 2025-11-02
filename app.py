from flask import Flask, render_template, request, jsonify, url_for, redirect, session, flash
from config import NGROK_URL
import sqlite3
import pandas as pd
import os
import secrets
import datetime
import socket
import hashlib
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"
DB_FILE = "database.db"

# --- PASSWORD HASH ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- INIT DATABASE ---
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row

        # Admin login table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        # Student login table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS student_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        # Devices table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT,
                location TEXT,
                hostname TEXT,
                ip_address TEXT,
                created_at TEXT,
                assigned_student TEXT,
                used INTEGER DEFAULT 0,
                comlab_id INTEGER DEFAULT 0,
                last_assigned_student TEXT
            )
        """)

        # Students master list (include plaintext password and status for admin view)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id TEXT PRIMARY KEY,
                name TEXT,
                grade_section TEXT,
                password TEXT DEFAULT '',
                status TEXT DEFAULT '',
                deleted INTEGER DEFAULT 0
            )
        """)

        # Active sessions table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_sessions
            (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pc_tag TEXT UNIQUE,
                student_id TEXT,
                student_name TEXT,
                login_time TEXT
            )
            """)

        # Device tokens table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE,
                created_at TEXT,
                used INTEGER DEFAULT 0
            )
        """)

        # Anomalies table (with cleared flag for soft-delete)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                student_id TEXT,
                pc_tag TEXT,
                anomaly_type TEXT,
                details TEXT,
                detected_at TEXT,
                detected_by TEXT,
                device_unit TEXT,
                student_name TEXT,
                last_student_name TEXT,
                cleared INTEGER DEFAULT 0,
                FOREIGN KEY (device_id) REFERENCES devices(id)
            )
        """)

        conn.commit()

        # Load students.xlsx (if exists) and upsert into students table
        if os.path.exists("students.xlsx"):
            try:
                df = pd.read_excel("students.xlsx")  # Columns: 'Student ID', 'Name', 'Grade', 'Section'
                cur = conn.cursor()
                for _, row in df.iterrows():
                    student_id = str(row.get('Student ID', '')).strip()
                    name = str(row.get('Name', '')).strip()
                    grade = str(row.get('Grade', '')).strip() if not pd.isna(row.get('Grade', '')) else ""
                    section = str(row.get('Section', '')).strip() if not pd.isna(row.get('Section', '')) else ""
                    grade_section = f"{grade} - Section {section}".strip(" -")

                    # preserve existing password/status if present
                    cur.execute("SELECT password, status FROM students WHERE id = ?", (student_id,))
                    existing = cur.fetchone()
                    existing_password = existing[0] if existing else ""
                    existing_status = existing[1] if existing else ""

                    cur.execute("""
                        INSERT OR REPLACE INTO students (id, name, grade_section, password, status)
                        VALUES (?, ?, ?, ?, ?)
                    """, (student_id, name, grade_section, existing_password, existing_status))
                conn.commit()
                print("✅ Students imported/updated from students.xlsx")
            except Exception as e:
                print("⚠️ Error loading students.xlsx:", e)
        else:
            print("⚠️ No students.xlsx file found.")

init_db()

# --- CREATE DEFAULT ADMIN ---
def create_admin(username="admin", password="admin123"):

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
create_admin()

def create_student(student_id, name, password, grade_section):
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        # Save hashed password for login
        cur.execute("INSERT OR REPLACE INTO student_users (username, password) VALUES (?, ?)", (student_id, hashed_pw))
        # Save plaintext password for admin viewing
        cur.execute("""
            INSERT OR REPLACE INTO students (id, name, grade_section, password)
            VALUES (?, ?, ?, ?)
        """, (student_id, name, grade_section, password))
        conn.commit()

# --- INDEX / ROLE SELECTION ---
@app.route('/')
def index():
    options = [
        {"id": 1, "name": "Student", "icon": "icons/students.png", "route": "/login/student"},
        {"id": 2, "name": "Admin", "icon": "icons/admin.png", "route": "/login/admin"},
    ]
    return render_template("index.html", options=options)

# --- ADMIN LOGIN ---
@app.route("/login/admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM admins WHERE username = ? AND password = ?", (username, password))
            admin = cur.fetchone()
            if admin:
                session["admin"] = username
                flash("✅ Logged in successfully")
                return redirect(url_for("dashboard"))
            else:
                flash("❌ Invalid username or password")
    return render_template("login_admin.html")

# --- STUDENT LOGIN ---
@app.route("/login/student", methods=["GET", "POST"])
def login_student():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        pc_tag = request.form.get("pc_tag") or request.args.get("pc_tag") or socket.gethostname()

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM student_users WHERE username = ? AND password = ?", (username, password))
            student = cur.fetchone()

        if student:
            session["student"] = username
            session["pc_tag"] = pc_tag
            flash("✅ Logged in successfully")


            hostname = socket.gethostname()
            with sqlite3.connect(DB_FILE) as conn:
                cur = conn.cursor()
                cur.execute("SELECT tag FROM devices WHERE hostname = ? ", (hostname,))
                row = cur.fetchone()
                pc_tag = row[0] if row else hostname

            with sqlite3.connect(DB_FILE) as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM students WHERE id = ?", (username,))
                row = cur.fetchone()
                student_name = row[0] if row else username

            # Notify peripherals / system of login
            try:
                import requests
                requests.post(f"{NGROK_URL}/api/student_login_event", json={
                    "pc_tag": pc_tag,
                    "student_id": username,
                    "student_name": student_name
                }, timeout=5)
                print(f"✅ Synced login: {student_name} on {pc_tag}")
            except Exception as e:
                print(f"⚠️ Failed to sync student login: {e}")

            session["student"] = username
            return redirect(url_for("student_dashboard"))
        else:
            flash("❌ Invalid username or password")

    return render_template("login_student.html")

# --- REGISTER ADMIN ---
@app.route("/register_admin", methods=["GET", "POST"])
def register_admin():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        confirm = request.form["confirm_password"].strip()
        secret_code = request.form["secret_code"].strip()

        # ✅ SECURITY CHECK
        ADMIN_SECRET = "SuperSecureAdminKey2025"  # Change this to something private!

        if secret_code != ADMIN_SECRET:
            flash("❌ Invalid admin secret code. Access denied.")
            return render_template("register_admin.html")

        if password != confirm:
            flash("❌ Passwords do not match.")
            return render_template("register_admin.html")

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM admins WHERE username = ?", (username,))
            existing = cur.fetchone()
            if existing:
                flash("⚠️ Admin username already exists.")
                return render_template("register_admin.html")

            cur.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (username, password))
            conn.commit()

        flash("✅ Admin account created successfully.")
        return redirect(url_for("login_admin"))

    return render_template("register_admin.html")

# --- REGISTER STUDENT ---
@app.route("/register_student", methods=["GET", "POST"])
def register_student():
    if request.method == "POST":
        student_id = request.form["username"].strip()
        password = request.form["password"].strip()
        confirm_password = request.form["confirm_password"].strip()

        # Check if passwords match
        if password != confirm_password:
            flash("❌ Passwords do not match")
            return render_template("register_student.html")

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()

            # 1️⃣ Check if ID exists in the students masterlist
            cur.execute("SELECT name, grade_section FROM students WHERE id = ?", (student_id,))
            existing = cur.fetchone()

            if not existing:
                flash("❌ This ID number is not found in the database of the program.")
                return render_template("register_student.html")

            student_name, grade_section = existing

            # 2️⃣ Check if already registered in student_users
            cur.execute("SELECT * FROM student_users WHERE username = ?", (student_id,))
            already = cur.fetchone()

            if already:
                flash("⚠️ This student ID is already registered.")
                return render_template("register_student.html")

            # 3️⃣ Register student (insert hashed password)
            hashed_pw = hash_password(password)
            cur.execute("INSERT INTO student_users (username, password) VALUES (?, ?)", (student_id, hashed_pw))

            # Save plaintext password in the `students` table for admin viewing
            cur.execute("""
                UPDATE students 
                SET password = ?, status = 'Registered'
                WHERE id = ?
            """, (password, student_id))

            conn.commit()

        flash(f"✅ Account created successfully for {student_name} ({student_id}). Please login.")
        return redirect(url_for("login_student"))

    return render_template("register_student.html")
@app.route("/student/dashboard")
def student_dashboard():
    student_id = session.get("student")
    if not student_id:
        flash("Please log in first.")
        return redirect(url_for("login_student"))

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Get student name
        cur.execute("SELECT name FROM students WHERE id = ?", (student_id,))
        row = cur.fetchone()
        student_name = row["name"] if row else student_id

        # Get anomalies for this student
        cur.execute("""
                    SELECT a.anomaly_type,
                           a.details,
                           a.detected_at,
                           d.tag       AS pc_tag,
                           d.comlab_id AS comlab_name
                    FROM anomalies a
                             JOIN devices d ON a.device_id = d.id
                    WHERE a.student_id = ?
                      AND (a.cleared = 0 OR a.cleared IS NULL)
                      AND (a.details NOT LIKE '%HIDClass%' OR a.details IS NULL)
                      AND (a.details NOT LIKE '%USB Input Device ((Standard system devices))%' OR a.details IS NULL)
                    ORDER BY a.detected_at DESC
                    """, (student_id,))

        anomalies = cur.fetchall()

    return render_template("student_dashboard.html",
                           student={"id_number": student_id, "name": student_name},
                           anomalies=anomalies)

# --- LOGOUT ---
@app.route("/logout")
def logout():
    pc_tag = session.get("pc_tag")
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()

            if pc_tag:
                # clear device assignment
                cur.execute("""
                    UPDATE devices
                    SET used = 0
                    WHERE hostname = ? OR tag = ?
                """, (pc_tag, pc_tag))

                # remove active session entry
                cur.execute("DELETE FROM active_sessions WHERE pc_tag = ?", (pc_tag,))
                conn.commit()
                print(f"👋 [logout] Cleared session and assignment for {pc_tag}")

        session.pop("admin", None)
        session.pop("student", None)

        flash("✅ Logged out successfully")
        return redirect(url_for("index"))

    except Exception as e:
        print(f"⚠️ [logout] Error clearing session for {pc_tag}: {e}")
        return jsonify({"error": str(e)}), 500
@app.route("/api/logout", methods=["GET"])
def api_logout():
    pc_tag = session.get("pc_tag")
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()

            cur.execute("""
                UPDATE devices
                SET used = '0'
                WHERE hostname = ? OR tag = ?
            """, (pc_tag, pc_tag))

            cur.execute("DELETE FROM active_sessions WHERE pc_tag = ?", (pc_tag,))
            conn.commit()

        print(f"✅ [api_logout] Cleared assignment and session for {pc_tag}")
        return jsonify({"status": "cleared", "pc_tag": pc_tag}), 200

    except Exception as e:
        print(f"⚠️ [api_logout] Error clearing session for {pc_tag}: {e}")
        return jsonify({"error": str(e)}), 500

# --- DASHBOARD ---
@app.route("/dashboard")
def dashboard():
    comlabs = [
        {"id": 1, "name": "ComLab 1", "icon": "icons/comlab.png"},
        {"id": 2, "name": "ComLab 2", "icon": "icons/comlab.png"},
        {"id": 3, "name": "ComLab 3", "icon": "icons/comlab.png"},
    ]
    return render_template("dashboard.html", comlabs=comlabs)

@app.route("/api/verify_student", methods=["POST"])
def verify_student():
    data = request.get_json()
    student_id = data.get("student_id")
    password = data.get("password")

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()

        cur.execute("SELECT id, name FROM students WHERE id = ?", (student_id,))
        row = cur.fetchone()

        cur.execute("SELECT password FROM student_users WHERE username = ?", (student_id,))
        pw_row = cur.fetchone()

        if row and pw_row and pw_row[0] == hash_password(password):
            return jsonify({"valid": True, "name": row[1]})
        else:
            return jsonify({"valid": False})

@app.route("/comlab/<int:comlab_id>")
def comlab_view(comlab_id):
    logged_in_student = session.get("student")

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # 🖥️ Fetch all devices under this comlab
        cur.execute("""
            SELECT id,tag, assigned_student, used
            FROM devices d
            WHERE d.comlab_id = ?
        """, (comlab_id,))
        devices = [dict(row) for row in cur.fetchall()]

        # ⚠️ Fetch anomalies detected within the last 10 minutes (not cleared)
        cur.execute("""
            SELECT 
                a.device_id,
                d.tag AS pc_tag,
                a.anomaly_type,
                a.details,
                a.student_name,
                a.student_id,
                a.detected_at
            FROM anomalies a
            JOIN devices d ON a.device_id = d.id
            WHERE d.comlab_id = ?
              AND datetime(a.detected_at) >= datetime('now', '-10 minutes')
              AND IFNULL(a.cleared, 0) = 0
            ORDER BY a.detected_at DESC
        """, (comlab_id,))
        anomalies = [dict(row) for row in cur.fetchall()]

        # 🧠 Count anomalies per device for AI alerts
        faulty_devices = {}
        for row in anomalies:
            pc_tag = row["pc_tag"]
            faulty_devices[pc_tag] = faulty_devices.get(pc_tag, 0) + 1

        # 🧩 Build AI notification messages
        ai_alerts = []
        for pc_tag, count in faulty_devices.items():
            if count >= 3:  # You can adjust this threshold
                ai_alerts.append({
                    "pc_tag": pc_tag,
                    "count": count,
                    "message": f"Potential faulty device detected in {pc_tag} ({count} anomalies in last 10 mins)"
                })

    # ✅ Pass all data to template
    return render_template(
        "comlab_view.html",
        comlab_id=comlab_id,
        devices=devices,
        anomalies=anomalies,
        ai_alerts=ai_alerts,
        logged_in_student=logged_in_student
    )
# --- STUDENT LOGIN EVENT (PC-based) ---
@app.route("/api/student_login_event", methods=["POST"])
def student_login_event():
    data = request.get_json()
    student_id = data.get("student_id")
    student_name = data.get("student_name")
    pc_tag = data.get("pc_tag")

    if not all([student_id, student_name, pc_tag]):
        return jsonify({"error": "Missing required fields"}), 400

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()

        # Ensure device exists
        cur.execute("SELECT id FROM devices WHERE hostname = ? OR tag = ?", (pc_tag, pc_tag))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": f"Device {pc_tag} not found"}), 404

        device_id = row[0]

        # Update device info
        cur.execute("""
            UPDATE devices
            SET assigned_student = ?, used = 1
            WHERE id = ?
        """, (student_name, device_id))

        # Track in active_sessions
        cur.execute("""
            INSERT OR REPLACE INTO active_sessions (pc_tag, student_id, student_name, login_time)
            VALUES (?, ?, ?, datetime('now'))
        """, (pc_tag, student_id, student_name))

        conn.commit()

    print(f"✅ {student_name} logged in on {pc_tag}")
    return jsonify({"success": True, "device_id": device_id})

# --- STUDENT LOGOUT EVENT ---
@app.route("/api/student_logout_event", methods=["POST"])
def student_logout_event():
    data = request.get_json()
    pc_tag = data.get("pc_tag")

    if not pc_tag:
        return jsonify({"error": "Missing pc_tag"}), 400

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE devices
            SET last_assigned_student = assigned_student,
                assigned_student = NULL,
                used = 0
            WHERE hostname = ? OR tag = ?
        """, (pc_tag, pc_tag))

        # Remove active session
        cur.execute("DELETE FROM active_sessions WHERE pc_tag = ?", (pc_tag,))
        cur.execute("UPDATE devices SET used = 0 WHERE tag = ?", (pc_tag,))

        conn.commit()

    print(f"👋 Device {pc_tag} unassigned after logout.")
    return jsonify({"success": True})

# --- Assign / Logout Student ---
@app.route("/assign_student", methods=["POST"])
def assign_student():
    data = request.get_json()
    device_id = data.get("device_id")
    student_id = data.get("student")

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        if student_id == "logout":
            # LOGOUT: move assigned_student to last_assigned_student
            cur.execute("""
                UPDATE devices
                SET last_assigned_student = assigned_student,
                    assigned_student = NULL,
                    used = 0
                WHERE id = ?
            """, (device_id,))

        else:
            # ASSIGN: update current assigned_student
            cur.execute("""
                UPDATE devices
                SET assigned_student = ?, used = 1
                WHERE id = ?
            """, (student_id, device_id))
        conn.commit()

    return jsonify({"success": True})

@app.route("/generate_link", methods=["GET"])
def generate_link():
    token = secrets.token_urlsafe(16)
    created_at = datetime.datetime.now().isoformat()

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO device_tokens (token, created_at) VALUES (?, ?)",
            (token, created_at)
        )
        conn.commit()

    link = url_for("register_device", token=token, _external=True)
    return render_template("link_generated.html", link=link)

# --- Register Device Page ---
@app.route("/register_device/<token>", methods=["GET", "POST"])
def register_device(token):
    comlabs = [
        {"id": 1, "name": "ComLab 1"},
        {"id": 2, "name": "ComLab 2"},
        {"id": 3, "name": "ComLab 3"},
    ]

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, used FROM device_tokens WHERE token = ?", (token,))
        row = cur.fetchone()

        if not row:
            return "Invalid or expired link.", 400
        if row[1] == 1:
            return "This link has already been used.", 400

        if request.method == "POST":
            tag = request.form["tag"]
            location = request.form["location"]
            hostname = socket.gethostname()
            ip_addr = request.remote_addr
            created_at = datetime.datetime.now().isoformat()
            comlab_id = int(location)

            # --- Check if device already exists in another comlab ---
            cur.execute("""
                        SELECT comlab_id
                        FROM devices
                        WHERE tag = ?
                            OR hostname = ?
                        """, (tag, hostname))
            existing = cur.fetchone()

            if existing:
                return f"⚠️ Device already registered in ComLab {existing[0]}. Cannot register in another ComLab.", 400

            # --- Insert device since it's not registered anywhere else ---
            conn.execute("""
                         INSERT INTO devices (tag, location, hostname, ip_address, created_at, comlab_id)
                         VALUES (?, ?, ?, ?, ?, ?)
                         """, (tag, location, hostname, ip_addr, created_at, comlab_id))

            conn.execute("UPDATE device_tokens SET used = 1 WHERE id = ?", (row[0],))
            conn.commit()

            return render_template("success.html", tag=tag, hostname=hostname, ip=ip_addr)

    return render_template("register_device.html", comlabs=comlabs)

@app.route("/api/log_anomaly", methods=["POST"])
def api_log_anomaly():
    data = request.get_json()
    device_id = data.get("device_id")
    anomaly_type = data.get("anomaly_type")
    details = data.get("details", "")
    detected_by = data.get("detected_by", "Unknown")
    pc_tag = data.get("pc_tag", "Unknown")

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()

        # Get currently assigned_student (this is usually stored as student_name in devices)
        cur.execute("SELECT assigned_student FROM devices WHERE id = ?", (device_id,))
        row = cur.fetchone()
        assigned = row[0] if row and row[0] else None

        # Try to resolve student_id (id/username) from students table by name
        student_id = None
        student_name = None
        # make sure both id and name are defined
        if assigned:
            cur.execute("SELECT id, name FROM students WHERE name = ?", (assigned,))
            row = cur.fetchone()
            if row:
                student_id = row[0]
                student_name = row[1]
            else:
                student_id = assigned
                student_name = assigned
        else:
            student_id = "Unassigned"
            student_name = "Unassigned"

        # Deduplicate recent identical anomalies for same pc_tag+student+type
        cur.execute("""
            SELECT COUNT(*) FROM anomalies
            WHERE (student_id = ? OR student_name = ?) 
              AND anomaly_type = ? 
              AND pc_tag = ?
              AND datetime(detected_at) >= datetime('now', '-1 minute')
        """, (student_id, student_name, anomaly_type, pc_tag))
        already_exists = cur.fetchone()[0]

        if already_exists:
            print(f"⚠️ Duplicate anomaly ignored for {student_name} ({anomaly_type}) on {pc_tag}")
            return jsonify({"status": "duplicate_ignored"})

        # Insert anomaly
        cur.execute("""
                    INSERT INTO anomalies (device_id, student_id, student_name, pc_tag, anomaly_type, details,
                                           detected_at, detected_by)
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                    """, (device_id, student_id, student_name, pc_tag, anomaly_type, details, detected_by))
        conn.commit()

    print(f"Logged anomaly: device={device_id}, student={student_name}, type={anomaly_type}")
    return jsonify({"status": "logged"})

@app.route("/comlab/<comlab_id>/anomalies")
def view_reports(comlab_id):
    date_filter = request.args.get("date", "")
    device_filter = request.args.get("device_unit", "")
    type_filter = request.args.get("anomaly_type", "")

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = """
            SELECT a.id, a.device_id, a.student_id, a.student_name,
                   a.anomaly_type, a.details, a.detected_at,
                   d.tag AS device_tag
            FROM anomalies a
            JOIN devices d ON a.device_id = d.id
            WHERE d.comlab_id = ? AND a.cleared = 0
        """
        params = [comlab_id]

        if date_filter:
            query += " AND DATE(a.detected_at) = ?"
            params.append(date_filter)
        if device_filter:
            query += " AND d.tag = ?"
            params.append(device_filter)
        if type_filter:
            query += " AND a.anomaly_type = ?"
            params.append(type_filter)

        query += " ORDER BY a.detected_at DESC"

        cur.execute(query, params)
        anomalies = cur.fetchall()

        cur.execute("SELECT tag FROM devices WHERE comlab_id = ?", (comlab_id,))
        devices = cur.fetchall()

        cur.execute("SELECT DISTINCT anomaly_type FROM anomalies")
        anomaly_types = [r["anomaly_type"] for r in cur.fetchall()]

    return render_template(
        "view_reports.html",
        comlab_id=comlab_id,
        anomalies=anomalies,
        devices=devices,
        anomaly_types=anomaly_types,
    )

@app.route("/api/current_student", methods=["GET"])
def current_student():
    """Return the currently logged-in student for a given PC"""
    pc_tag = request.args.get("pc_tag")

    if not pc_tag:
        return jsonify({"error": "Missing pc_tag"}), 400

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT student_id, student_name FROM active_sessions WHERE pc_tag=?", (pc_tag,))
        row = cur.fetchone()

    if row:
        return jsonify({
            "student_id": row[0],
            "student_name": row[1]
        })
    else:
        return jsonify({
            "student_id": None,
            "student_name": None
        })

@app.route("/api/get_device_id")
def get_device_id():
    pc_tag = request.args.get("pc_tag")
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM devices WHERE hostname = ? OR tag = ?", (pc_tag, pc_tag))
        row = cur.fetchone()
        if row:
            return jsonify({"device_id": row[0]})
    return jsonify({"device_id": None})

@app.route("/comlab/<int:comlab_id>")
def anomalies_view(comlab_id):
    logged_in_student = session.get("student")  # get the logged-in student username, if any

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row

        devices_cursor = conn.execute("""
            SELECT id, tag, assigned_student, used
            FROM devices
            WHERE comlab_id = ?
        """, (comlab_id,))
        devices = [dict(row) for row in devices_cursor.fetchall()]

    # Update devices to reflect currently-logged-in student (if device not used)
    for device in devices:
        if device["used"]:
            device["assigned_student"] = device["assigned_student"]
        else:
            device["assigned_student"] = logged_in_student if logged_in_student else None


    return render_template("comlab_view.html", comlab_id=comlab_id, devices=devices)

@app.route("/comlab/<int:comlab_id>/summary")
def comlab_summary(comlab_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Count total devices in the comlab
        cur.execute("SELECT COUNT(*) AS total_devices FROM devices WHERE comlab_id = ?", (comlab_id,))
        total_devices = cur.fetchone()["total_devices"]

        # Count total anomalies linked to devices in this comlab (ignore cleared and nuisance details)
        cur.execute("""
            SELECT COUNT(a.id) AS total_anomalies
            FROM anomalies a
            JOIN devices d ON a.device_id = d.id
            WHERE d.comlab_id = ?
              AND a.cleared = 0
              AND (a.details NOT LIKE '%HIDClass%' OR a.details IS NULL)
              AND (a.details NOT LIKE '%USB Input Device ((Standard system devices))%' OR a.details IS NULL)
              AND (a.cleared = 0 OR a.cleared IS NULL)
        """, (comlab_id,))
        total_anomalies = cur.fetchone()["total_anomalies"]

        # Count distinct students with anomaly records in this comlab
        cur.execute("""
            SELECT COUNT(DISTINCT COALESCE(a.student_id, a.student_name)) AS students_with_anomalies
            FROM anomalies a
            JOIN devices d ON a.device_id = d.id
            WHERE d.comlab_id = ?
              AND a.cleared = 0
              AND (a.details NOT LIKE '%HIDClass%' OR a.details IS NULL)
              AND (a.details NOT LIKE '%USB Input Device ((Standard system devices))%' OR a.details IS NULL)
                AND (a.cleared = 0 OR a.cleared IS NULL)
        """, (comlab_id,))
        students_with_anomalies = cur.fetchone()["students_with_anomalies"]

        # Per-device anomaly counts
        cur.execute("""
                    SELECT d.tag       AS device_tag,
                           COUNT(a.id) AS anomaly_count
                    FROM anomalies a
                             JOIN devices d ON a.device_id = d.id
                    WHERE d.comlab_id = ? AND a.cleared = 0
                          AND (a.details NOT LIKE '%HIDClass%' OR a.details IS NULL)
                          AND (a.details NOT LIKE '%USB Input Device ((Standard system devices))%' OR a.details IS NULL)
                        AND (a.cleared = 0 OR a.cleared IS NULL)
                    GROUP BY d.id
                    ORDER BY anomaly_count DESC
                    """, (comlab_id,))
        summary = cur.fetchall()

    return render_template(
        "summary.html",
        summary=summary,
        comlab_id=comlab_id,
        total_devices=total_devices,
        total_anomalies=total_anomalies,
        students_with_anomalies=students_with_anomalies
    )

@app.route("/students")
def view_students():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Get all students
        cur.execute("""
            SELECT s.id AS student_id, s.name AS student_name, s.grade_section
            FROM students s
            WHERE deleted = 0 or NULL
            ORDER BY s.name ASC
        """)
        students = cur.fetchall()

        # Count anomalies per student (excluding cleared)
        cur.execute("""
            SELECT student_id, COUNT(*) AS anomaly_count
            FROM anomalies a JOIN devices d ON a.device_id = d.id
            WHERE student_id IS NOT NULL 
              AND TRIM(student_id) != ''
              AND (a.cleared = 0 OR a.cleared IS NULL)
            AND (a.details NOT LIKE '%HIDClass%' OR a.details IS NULL)
            AND (a.details NOT LIKE '%USB Input Device ((Standard system devices))%' OR a.details IS NULL)
            
            GROUP BY a.student_id
        """)
        anomaly_counts = {row["student_id"]: row["anomaly_count"] for row in cur.fetchall()}

        # Get passwords
        cur.execute("SELECT id AS student_id, password FROM students")
        passwords = {row["student_id"]: row["password"] for row in cur.fetchall()}

    student_data = []
    for s in students:
        sid = s["student_id"]
        anomaly_count = anomaly_counts.get(sid, 0)
        password = passwords.get(sid, "")
        student_data.append({
            "student_id": sid,
            "student_name": s["student_name"],
            "grade_section": s["grade_section"] or "—",
            "password": password,
            "has_anomaly": anomaly_count > 0,
            "anomaly_count": anomaly_count
        })

    return render_template("students.html", students=student_data)

@app.route("/api/delete_anomaly", methods=["POST"])
def delete_anomaly():
    data = request.get_json()
    anomaly_id = data.get("id")
    if not anomaly_id:
        return jsonify({"success": False, "error": "Missing anomaly id"}), 400

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE anomalies SET cleared=1 WHERE id=?", (anomaly_id,))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"success": False, "error": "No anomaly found"}), 404

    return jsonify({"success": True}), 200


# ✅ Change student password (updates hashed login and plaintext admin view)
@app.route("/students/<student_id>/change_password", methods=["POST"])
def change_student_password(student_id):
    new_pass = request.form.get("new_password")
    if not new_pass:
        flash("⚠️ Password cannot be empty.")
        return redirect(url_for("view_students"))

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        # store hashed in student_users (login)
        hashed = hash_password(new_pass)
        cur.execute("UPDATE student_users SET password = ? WHERE username = ?", (hashed, student_id))
        # store plaintext in students table for admin viewing (only if admin wants)
        cur.execute("UPDATE students SET password = ? WHERE id = ?", (new_pass, student_id))
        conn.commit()

    flash(f"🔑 Password changed for {student_id}")
    return redirect(url_for("view_students"))
@app.route("/api/student_anomalies/<student_id>")
def api_student_anomalies(student_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT a.anomaly_type,a.details, a.detected_at, a.pc_tag, a.id
            FROM anomalies a JOIN devices d ON a.device_id = d.id
            WHERE a.student_id = ? AND a.cleared = 0
            AND (a.details NOT LIKE '%HIDClass%' OR a.details IS NULL)
            AND (a.details NOT LIKE '%USB Input Device ((Standard system devices))%' OR a.details IS NULL)
            ORDER BY a.detected_at DESC
        """, (student_id,))
        anomalies = [dict(row) for row in cur.fetchall()]
    return jsonify(anomalies)
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/api/deleted_anomalies")
def deleted_anomalies():
    comlab_id = request.args.get("comlab_id")
    date_filter = request.args.get("date", "")
    device_filter = request.args.get("device_unit", "")
    type_filter = request.args.get("anomaly_type", "")

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Select same fields as view_reports but only cleared=1
        query = """
            SELECT a.id, a.device_id, a.student_id, a.student_name,
                   a.anomaly_type, a.details, a.detected_at,
                   d.tag AS device_tag
            FROM anomalies a
            JOIN devices d ON a.device_id = d.id
            WHERE d.comlab_id = ? AND a.cleared = 1
        """
        params = [comlab_id]

        if date_filter:
            query += " AND DATE(a.detected_at) = ?"
            params.append(date_filter)
        if device_filter:
            query += " AND d.tag = ?"
            params.append(device_filter)
        if type_filter:
            query += " AND a.anomaly_type = ?"
            params.append(type_filter)

        query += " ORDER BY a.detected_at DESC"

        cur.execute(query, params)
        deleted_anomalies = cur.fetchall()

    # Convert to list of dicts for JSON
    data = [dict(row) for row in deleted_anomalies]
    return jsonify(data)


@app.route("/api/restore_anomaly", methods=["POST"])
def restore_anomaly():
    data = request.get_json()
    anomaly_id = data.get("id")

    conn = get_db_connection()
    conn.execute("UPDATE anomalies SET cleared = 0 WHERE id = ?", (anomaly_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True})
@app.route("/api/delete_device", methods=["POST"])
def delete_device():
    data = request.get_json()
    device_id = data.get("id")

    if not device_id:
        return jsonify({"success": False, "message": "No device ID provided"}), 400

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()

            # Optional: check if device exists
            cur.execute("SELECT id FROM devices WHERE id = ?", (device_id,))
            if not cur.fetchone():
                return jsonify({"success": False, "message": "Device not found"}), 404

            # Delete the device
            cur.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            conn.commit()

        return jsonify({"success": True})

    except Exception as e:
        print("Error deleting device:", e)
        return jsonify({"success": False, "message": str(e)}), 500
@app.route("/delete_student/<student_id>", methods=["POST"])
def delete_student(student_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE students SET deleted = 1 WHERE id = ?", (student_id,))
        cur.execute("DELETE FROM student_users WHERE username = ?", (student_id,))
        conn.commit()
    flash(f"Student {student_id} has been deleted.", "success")
    return redirect("/students")
@app.route("/admins")
def view_admins():
    # Only allow access if logged in as an admin
    if "admin" not in session:
        flash("❌ Please log in as admin first.")
        return redirect(url_for("login_admin"))

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, username, password FROM admins ORDER BY id ASC")
        admins = cur.fetchall()

    return render_template("admins.html", admins=admins)
@app.route("/admins/<int:admin_id>/change_password", methods=["POST"])
def change_admin_password(admin_id):
    new_password = request.form.get("new_password")

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE admins SET password = ? WHERE id = ?", (new_password, admin_id))
        conn.commit()

    flash("✅ Admin password updated successfully.")
    return redirect(url_for("view_admins"))
@app.route("/delete_admin/<int:admin_id>")
def delete_admin(admin_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
        conn.commit()

    flash("✅ Admin removed successfully.")
    return redirect(url_for("view_admins"))

if __name__ == "__main__":
    init_db()  # ensure tables exist
    app.run(debug=True)
