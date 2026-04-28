from flask import Flask, request, render_template, session, redirect
import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "super_secret_key_change_me"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def log_action(user_id, action, resource, resource_id=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, action, resource, resource_id, request.remote_addr)
    )
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <h1>AuthX App</h1>
    <a href="/register">Register</a> |
    <a href="/login">Login</a> |
    <a href="/forgot-password">Forgot Password</a>
    """


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = request.form.get("username")
    password = request.form.get("password")

    if not email or not password or len(password) < 8:
        return "Invalid input"

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            (email, password_hash, "ANALYST")
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return "Invalid input"

    conn.close()
    return "User created<br><a href='/login'>Login</a>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, password_hash, locked, failed_attempts FROM users WHERE email = ?",
        (email,)
    )
    row = cur.fetchone()

    if row is None:
        conn.close()
        return "Invalid credentials"

    user_id, password_hash, locked, failed_attempts = row

    if locked:
        conn.close()
        log_action(user_id, "LOGIN_LOCKED", "auth")
        return "Account locked"

    if not bcrypt.checkpw(password.encode(), password_hash.encode()):
        failed_attempts += 1

        if failed_attempts >= 3:
            cur.execute(
                "UPDATE users SET locked = 1, failed_attempts = ? WHERE id = ?",
                (failed_attempts, user_id)
            )
        else:
            cur.execute(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (failed_attempts, user_id)
            )

        conn.commit()
        conn.close()
        log_action(user_id, "LOGIN_FAILED", "auth")
        return "Invalid credentials"

    cur.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    session.clear()
    session.permanent = True
    session["user_id"] = user_id

    log_action(user_id, "LOGIN_SUCCESS", "auth")
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    return """
    <h1>Dashboard</h1>
    <a href="/create-ticket">Create Ticket</a><br>
    <a href="/tickets">View Tickets</a><br>
    <a href="/search">Search</a><br>
    <a href="/logout">Logout</a>
    """


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        log_action(user_id, "LOGOUT", "auth")

    session.clear()
    return redirect("/login")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("username")
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
    row = cur.fetchone()

    if row:
        user_id = row[0]
        cur.execute(
            """
            INSERT INTO password_resets (user_id, token, expires_at, used)
            VALUES (?, ?, ?, 0)
            """,
            (user_id, token, expires_at)
        )
        conn.commit()
        log_action(user_id, "PASSWORD_RESET_REQUEST", "auth")

    conn.close()

    return f"""
    If the account exists, a reset link was generated.<br>
    <a href="/reset-password?token={token}">Reset Password</a>
    """


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        token = request.args.get("token")
        return render_template("reset_password.html", token=token)

    token = request.form.get("token")
    new_password = request.form.get("password")

    if not new_password or len(new_password) < 8:
        return "Invalid input"

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, user_id, expires_at, used
        FROM password_resets
        WHERE token = ?
        """,
        (token,)
    )
    row = cur.fetchone()

    if row is None:
        conn.close()
        return "Invalid or expired token"

    reset_id, user_id, expires_at, used = row

    if used or datetime.utcnow() > datetime.fromisoformat(expires_at):
        conn.close()
        return "Invalid or expired token"

    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    cur.execute(
        "UPDATE users SET password_hash = ?, failed_attempts = 0, locked = 0 WHERE id = ?",
        (password_hash, user_id)
    )

    cur.execute(
        "UPDATE password_resets SET used = 1 WHERE id = ?",
        (reset_id,)
    )

    conn.commit()
    conn.close()

    log_action(user_id, "PASSWORD_RESET_SUCCESS", "auth")
    return "Password reset successful<br><a href='/login'>Login</a>"


@app.route("/create-ticket", methods=["GET", "POST"])
def create_ticket():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "GET":
        return render_template("create_ticket.html")

    title = request.form.get("title")
    description = request.form.get("description")
    severity = request.form.get("severity")
    status = request.form.get("status")

    if severity not in ["LOW", "MED", "HIGH"]:
        return "Invalid severity"

    if status not in ["OPEN", "IN_PROGRESS", "RESOLVED"]:
        return "Invalid status"

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO tickets (title, description, severity, status, owner_id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (title, description, severity, status, session["user_id"])
    )

    ticket_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_action(session["user_id"], "CREATE_TICKET", "ticket", str(ticket_id))
    return "Ticket created<br><a href='/tickets'>View tickets</a>"


@app.route("/tickets")
def tickets():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, title, description, severity, status, owner_id
        FROM tickets
        WHERE owner_id = ?
        """,
        (session["user_id"],)
    )

    rows = cur.fetchall()
    conn.close()

    html = "<h1>My Tickets</h1>"
    html += "<a href='/dashboard'>Dashboard</a><br><br>"

    for t in rows:
        html += f"""
        <div style="border:1px solid black; margin:10px; padding:10px;">
            <p><b>ID:</b> {t[0]}</p>
            <p><b>Title:</b> {t[1]}</p>
            <p><b>Description:</b> {t[2]}</p>
            <p><b>Severity:</b> {t[3]}</p>
            <p><b>Status:</b> {t[4]}</p>
            <p><b>Owner ID:</b> {t[5]}</p>
            <a href="/edit-ticket/{t[0]}">Edit</a> |
            <a href="/delete-ticket/{t[0]}">Delete</a>
        </div>
        """

    return html


@app.route("/edit-ticket/<int:id>", methods=["GET", "POST"])
def edit_ticket(id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, title, description, severity, status, owner_id
        FROM tickets
        WHERE id = ? AND owner_id = ?
        """,
        (id, session["user_id"])
    )

    ticket = cur.fetchone()

    if ticket is None:
        conn.close()
        return "Access denied or ticket not found"

    if request.method == "GET":
        conn.close()
        return render_template("edit_ticket.html", ticket=ticket)

    title = request.form.get("title")
    description = request.form.get("description")
    severity = request.form.get("severity")
    status = request.form.get("status")

    if severity not in ["LOW", "MED", "HIGH"]:
        conn.close()
        return "Invalid severity"

    if status not in ["OPEN", "IN_PROGRESS", "RESOLVED"]:
        conn.close()
        return "Invalid status"

    cur.execute(
        """
        UPDATE tickets
        SET title = ?, description = ?, severity = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND owner_id = ?
        """,
        (title, description, severity, status, id, session["user_id"])
    )

    conn.commit()
    conn.close()

    log_action(session["user_id"], "EDIT_TICKET", "ticket", str(id))
    return "Ticket updated<br><a href='/tickets'>View tickets</a>"


@app.route("/delete-ticket/<int:id>")
def delete_ticket(id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM tickets WHERE id = ? AND owner_id = ?",
        (id, session["user_id"])
    )

    conn.commit()
    conn.close()

    log_action(session["user_id"], "DELETE_TICKET", "ticket", str(id))
    return "Ticket deleted<br><a href='/tickets'>View tickets</a>"


@app.route("/search", methods=["GET", "POST"])
def search():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "GET":
        return render_template("search.html")

    query = request.form.get("query")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, title, description, severity, status, owner_id
        FROM tickets
        WHERE owner_id = ?
        AND (title LIKE ? OR description LIKE ?)
        """,
        (session["user_id"], f"%{query}%", f"%{query}%")
    )

    rows = cur.fetchall()
    conn.close()

    html = "<h1>Search Results</h1>"
    html += "<a href='/dashboard'>Dashboard</a><br><br>"

    for t in rows:
        html += f"""
        <div style="border:1px solid black; margin:10px; padding:10px;">
            <p><b>ID:</b> {t[0]}</p>
            <p><b>Title:</b> {t[1]}</p>
            <p><b>Description:</b> {t[2]}</p>
            <p><b>Severity:</b> {t[3]}</p>
            <p><b>Status:</b> {t[4]}</p>
            <p><b>Owner ID:</b> {t[5]}</p>
        </div>
        """

    log_action(session["user_id"], "SEARCH_TICKETS", "ticket")
    return html


if __name__ == "__main__":
    app.run(debug=True)
    
