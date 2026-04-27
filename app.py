from flask import Flask, request, render_template, session, redirect
import sqlite3

app = Flask(__name__)
app.secret_key = "secret123"  


def get_db():
    return sqlite3.connect("users.db")


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

    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password)
    )

    conn.commit()
    conn.close()

    return "User created"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    conn.close()

    if row is None:
        return "User not found" 

    if row[0] != password:
        return "Wrong password" 
    session["user"] = username
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return "Not logged in"

    return f"""
    <h1>Dashboard</h1>
    <p>Welcome {session['user']}</p>
    <a href="/create-ticket">Create Ticket</a><br>
    <a href="/tickets">View Tickets</a><br>
    <a href="/search">Search</a><br>
    <a href="/logout">Logout</a>
    """


@app.route("/logout")
def logout():
    session.clear()
    return "Logged out"


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    username = request.form.get("username")

    token = username + "123"  

    return f"""
    Token: {token}<br>
    <a href="/reset-password?token={token}">Reset</a>
    """


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        token = request.args.get("token")
        return render_template("reset_password.html", token=token)

    token = request.form.get("token")
    new_password = request.form.get("password")

    username = token.replace("123", "")  

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (new_password, username)
    )

    conn.commit()
    conn.close()

    return "Password reset successful"


@app.route("/create-ticket", methods=["GET", "POST"])
def create_ticket():
    if "user" not in session:
        return "Not logged in"

    if request.method == "GET":
        return render_template("create_ticket.html")

    title = request.form.get("title")
    description = request.form.get("description")
    status = request.form.get("status")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO tickets (title, description, status, owner) VALUES (?, ?, ?, ?)",
        (title, description, status, session["user"])
    )

    conn.commit()
    conn.close()

    return "Ticket created"


@app.route("/tickets")
def tickets():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM tickets")  
    rows = cur.fetchall()

    conn.close()

    html = "<h1>Tickets</h1>"
    html += "<a href='/dashboard'>Dashboard</a><br><br>"

    for t in rows:
        html += f"""
        <div style="border:1px solid black; margin:10px; padding:10px;">
            <p><b>ID:</b> {t[0]}</p>
            <p><b>Title:</b> {t[1]}</p>
            <p><b>Description:</b> {t[2]}</p>
            <p><b>Status:</b> {t[3]}</p>
            <p><b>Owner:</b> {t[4]}</p>
            <a href="/edit-ticket/{t[0]}">Edit</a> |
            <a href="/delete-ticket/{t[0]}">Delete</a>
        </div>
        """

    return html


@app.route("/edit-ticket/<int:id>", methods=["GET", "POST"])
def edit_ticket(id):
    conn = get_db()
    cur = conn.cursor()

    if request.method == "GET":
        cur.execute("SELECT * FROM tickets WHERE id = ?", (id,))
        ticket = cur.fetchone()
        conn.close()
        return render_template("edit_ticket.html", ticket=ticket)

    title = request.form.get("title")

    cur.execute("UPDATE tickets SET title = ? WHERE id = ?", (title, id))
    conn.commit()
    conn.close()

    return "Updated"


@app.route("/delete-ticket/<int:id>")
def delete_ticket(id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM tickets WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    return "Deleted"


@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "GET":
        return render_template("search.html")

    query = request.form.get("query")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM tickets WHERE title LIKE ? OR description LIKE ?",
        (f"%{query}%", f"%{query}%")
    )

    rows = cur.fetchall()
    conn.close()

    return str(rows)


if __name__ == "__main__":
    app.run(debug=True)
