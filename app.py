from flask import Flask, request, render_template, session, redirect
import sqlite3

app = Flask(__name__)
app.secret_key = "123456789"


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

    return "User created<br><a href='/login'>Go to login</a>"


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
        return "Not logged in<br><a href='/login'>Login</a>"

    return f"""
    <h1>Dashboard</h1>
    <p>Welcome {session['user']}!</p>
    <a href="/logout">Logout</a>
    """


@app.route("/logout")
def logout():
    session.clear()
    return "Logged out<br><a href='/login'>Login again</a>"


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    username = request.form.get("username")

    token = username + "123"

    return f"""
    <h2>Reset token generated</h2>
    <p>Token: {token}</p>
    <a href="/reset-password?token={token}">Reset Password</a>
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

    return "Password reset successful<br><a href='/login'>Go to login</a>"


if __name__ == "__main__":
    app.run(debug=True)
