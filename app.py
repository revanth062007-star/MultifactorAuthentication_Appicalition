import os
import io
import base64
import sqlite3
from functools import wraps

import pyotp
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Set a random SECRET_KEY in the terminal before starting the app.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "SECRET_KEY is missing. In PowerShell run: "
        '$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"'
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Localhost demo only; use True behind HTTPS in production.
)

DB_NAME = "mfa_users.db"
ISSUER_NAME = "Cloud MFA College Demo"


def get_db():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL
            )
        """)


def make_qr_data_uri(provisioning_uri):
    image = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return "data:image/png;base64," + encoded


def login_required(view_function):
    @wraps(view_function)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") or not session.get("mfa_verified"):
            return redirect(url_for("login"))
        return view_function(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    if session.get("user_id") and session.get("mfa_verified"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or "@" not in email:
            flash("Please enter a valid email address.")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return render_template("register.html")

        secret = pyotp.random_base32()
        password_hash = generate_password_hash(password)

        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users (email, password_hash, totp_secret) VALUES (?, ?, ?)",
                    (email, password_hash, secret),
                )
        except sqlite3.IntegrityError:
            flash("That email is already registered. Please log in.")
            return render_template("register.html")

        uri = pyotp.TOTP(secret).provisioning_uri(
            name=email, issuer_name=ISSUER_NAME
        )
        session.clear()
        session["enrolling_email"] = email
        session["enrolling_secret"] = secret
        return render_template(
            "setup.html",
            email=email,
            qr_data_uri=make_qr_data_uri(uri),
            manual_key=secret,
        )

    return render_template("register.html")


@app.route("/confirm-setup", methods=["POST"])
def confirm_setup():
    email = session.get("enrolling_email")
    secret = session.get("enrolling_secret")
    code = request.form.get("code", "").strip()

    if not email or not secret:
        flash("Setup session expired. Please register again.")
        return redirect(url_for("register"))

    if not (code.isdigit() and len(code) == 6 and
            pyotp.TOTP(secret).verify(code, valid_window=1)):
        flash("Code not accepted. Check the authenticator app and try again.")
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=email, issuer_name=ISSUER_NAME
        )
        return render_template(
            "setup.html",
            email=email,
            qr_data_uri=make_qr_data_uri(uri),
            manual_key=secret,
        )

    session.clear()
    flash("Authenticator setup confirmed. You can now log in.")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Incorrect email or password.")
            return render_template("login.html")

        session.clear()
        session["pending_user_id"] = user["id"]
        session["otp_attempts"] = 0
        return redirect(url_for("verify_otp"))

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        attempts = int(session.get("otp_attempts", 0))

        if attempts >= 5:
            session.clear()
            flash("Too many incorrect codes. Please log in again.")
            return redirect(url_for("login"))

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE id = ?", (pending_id,)
            ).fetchone()

        if (user and code.isdigit() and len(code) == 6 and
                pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1)):
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            session["mfa_verified"] = True
            return redirect(url_for("dashboard"))

        session["otp_attempts"] = attempts + 1
        remaining = max(0, 5 - int(session["otp_attempts"]))
        flash(f"Incorrect or expired code. Attempts remaining: {remaining}.")

    return render_template("verify.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", email=session.get("email"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
