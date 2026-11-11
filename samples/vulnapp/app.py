# SENGAJA TIDAK SELAMAT - sampel untuk menguji secteam code_auditor. Jangan deploy.
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request, render_template_string

app = Flask(__name__)
app.secret_key = "supersecret123"          # hardcoded secret
DB_PASSWORD = "admin:P@ssw0rd!"


def db():
    return sqlite3.connect("users.db")


@app.route("/login", methods=["POST"])
def login():
    user = request.form["username"]
    pw = request.form["password"]
    # SQL injection
    q = f"SELECT * FROM users WHERE username = '{user}' AND password = '{pw}'"
    row = db().execute(q).fetchone()
    return "ok" if row else "fail"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # command injection
    out = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return out


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # SSTI
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/download")
def download():
    # path traversal
    fname = request.args.get("file")
    with open(os.path.join("/var/www/files", fname), "rb") as f:
        return f.read()


@app.route("/restore", methods=["POST"])
def restore():
    # insecure deserialization
    return str(pickle.loads(request.data))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
