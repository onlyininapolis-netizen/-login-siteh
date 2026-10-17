
import os
import hmac
import secrets
import sqlite3
from functools import wraps
from flask import (
    Flask, request, redirect, url_for,
    session, render_template_string, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "Set SECRET_KEY before starting the website."
    )

DB = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

with get_db() as con:
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

def check_csrf():
    token = request.form.get("csrf", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(token, expected):
        abort(400, "Invalid form token. Reload the page.")

def page(title, body):
    return render_template_string("""
    <!doctype html>
    <html lang="ar" dir="rtl">
    <head>
      <meta charset="utf-8">
      <meta name="viewport"
            content="width=device-width, initial-scale=1">
      <title>{{ title }}</title>
      <style>
        body {
          background:#101827; color:#fff;
          font-family:Arial,sans-serif;
          margin:0; padding:25px 14px;
        }
        main {
          max-width:400px; margin:50px auto;
          background:#1e293b; padding:25px;
          border-radius:16px;
        }
        h1 {color:#38bdf8}
        input,button {
          box-sizing:border-box; width:100%;
          padding:12px; margin:8px 0;
          border-radius:8px; font-size:16px;
        }
        input {border:1px solid #64748b}
        button {
          background:#0284c7; color:white;
          border:0; cursor:pointer;
        }
        a {color:#7dd3fc}
        .msg {line-height:1.8}
      </style>
    </head>
    <body><main>
      <h1>{{ title }}</h1>
      <div class="msg">{{ body|safe }}</div>
    </main></body>
    </html>
    """, title=title, body=body)

@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return page("موقعي الخاص", """
      <p>مرحبا بك فالموقع ديالي.</p>
      <p><a href="/register">إنشاء حساب</a></p>
      <p><a href="/login">تسجيل الدخول</a></p>
    """)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        check_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if len(email) > 254 or "@" not in email:
            return page("خطأ", "دخل بريد إلكتروني صحيح.")
        if len(password) < 12 or len(password) > 128:
            return page(
                "خطأ",
                "كلمة السر خاصها تكون بين 12 و128 حرف."
            )

        hashed = generate_password_hash(password)

        try:
            with get_db() as con:
                con.execute(
                    "INSERT INTO users(email,password_hash) VALUES (?,?)",
                    (email, hashed)
                )
        except sqlite3.IntegrityError:
            return page("ملاحظة", "هاد البريد مسجل من قبل.")

        return redirect(url_for("login"))

    token = csrf_token()
    return page("إنشاء حساب", f"""
      <form method="post">
        <input type="hidden" name="csrf" value="{token}">
        <label>البريد الإلكتروني</label>
        <input type="email" name="email"
               maxlength="254" required autocomplete="email">
        <label>كلمة السر (12 حرف على الأقل)</label>
        <input type="password" name="password"
               minlength="12" maxlength="128" required
               autocomplete="new-password">
        <button type="submit">إنشاء الحساب</button>
      </form>
      <a href="/login">عندي حساب</a>
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as con:
            user = con.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            return page("تعذر الدخول", "البريد أو كلمة السر غير صحيحة.")

        session.clear()
        session["user_id"] = user["id"]
        session["csrf"] = secrets.token_urlsafe(32)
        return redirect(url_for("dashboard"))

    token = csrf_token()
    return page("تسجيل الدخول", f"""
      <form method="post">
        <input type="hidden" name="csrf" value="{token}">
        <label>البريد الإلكتروني</label>
        <input type="email" name="email"
               required autocomplete="email">
        <label>كلمة السر</label>
        <input type="password" name="password"
               required autocomplete="current-password">
        <button type="submit">دخول</button>
      </form>
      <a href="/register">إنشاء حساب جديد</a>
    """)

@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    with get_db() as con:
        user = con.execute(
            "SELECT email FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    return page("الحساب ديالك", f"""
      <p>مرحبا بك، تسجيل الدخول ناجح.</p>
      <p>البريد ديالك: {user["email"]}</p>
      <form action="/logout" method="post">
        <input type="hidden" name="csrf"
               value="{csrf_token()}">
        <button type="submit">تسجيل الخروج</button>
      </form>
    """)

@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)

