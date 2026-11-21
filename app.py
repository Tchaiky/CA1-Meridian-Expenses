"""
Meridian Expenses — staff expense portal.

*** INTENTIONALLY VULNERABLE. TEACHING ARTEFACT. ***
Issued for CCT MSc Cybersecurity, Secure Programming and Scripting, CA1.
Do not deploy. Do not expose beyond localhost. Contains no real data.

There are more than six distinct, independently exploitable defects in this
file and its siblings. They are not marked.
"""
import hashlib
import os
import json
import sqlite3
import subprocess
import csv
import io
import re 
from io import BytesIO

from flask import (
    Flask, g, session, request, redirect, url_for, 
    render_template, abort, send_file, send_from_directory
)

app = Flask(__name__)
app.jinja_env.autoescape = True
app.secret_key = "meridian-dev-key"          # fixed across every deployment
DB = os.environ.get(
    "APP_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "expenses.db")
)



def db(): #Connect to SQL database
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext   #Close database connection after request
def close(_exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def hash_pw(pw):   #MD5 password hashing (another vulnerability)
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/", methods=["GET"])
def index():
    if "uid" not in session:  #If not logged in, redirected to log in.
        return redirect(url_for("login"))
        #Parameterisation to prevent SQL Injection.
    rows = db().execute(
        "SELECT * FROM claims WHERE user_id = ? ORDER BY id DESC",
        (session["uid"],)
    ).fetchall()
    return render_template("index.html", claims=rows, user=session.get("name"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        #Parameterised query to protect username
        q = ("SELECT id, name, role, password FROM users "
             "WHERE username = ?")
        row = db().execute(q, (u,)).fetchone()
        #Using MD5 password hashes.
        if row and row["password"] == hashlib.md5(p.encode()).hexdigest():
            session["uid"], session["name"], session["role"] = row["id"], row["name"], row["role"]
            return redirect(url_for("index"))
        exists = db().execute(
            "SELECT 1 FROM users WHERE username = ?", (u,)).fetchone()
        error = "Wrong password." if exists else "No such user."
    return render_template("login.html", error=error)


@app.route("/logout") #Logout and clear the session.
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/claim/<int:cid>")
def claim(cid):

    #Check authentication.
    if "uid" not in session:
        return redirect(url_for("login"))

    #Another parameterised query. 
    row = db().execute("SELECT * FROM claims WHERE id = ?", (cid,)).fetchone()
    if row is None:
        return "Not found", 404

    #Checks that the claim belongs to the user or user is an admin.
    if (row["user_id"] != session["uid"]
       and session.get("role") != "admin"):
       abort(403)
           
    return render_template("claim.html", c=row)


@app.route("/claim/new", methods=["POST"])
def new_claim():
    #If not logged in, redirect to login.
    if "uid" not in session:
        return redirect(url_for("login"))

    db().execute(
        "INSERT INTO claims (user_id, merchant, amount, note, status) "
        "VALUES (?,?,?,?,'pending')",
        (session.get("uid"), request.form.get("merchant"),
         request.form.get("amount"), request.form.get("note")))
    db().commit()
    return redirect(url_for("index"))


@app.route("/receipt")
def receipt():
    name = request.args.get("f", "")

    #Rejects empty filenames to reject directory traversal.
    if not name or name != os.path.basename(name):
        return "Invalid filename", 400

    receipts_dir = os.path.join(app.root_path, "receipts")

    return send_from_directory(receipts_dir, name)


@app.route("/export")
def export():
    month = request.args.get("month", "2026-09")

    #Validates the month parameter. 
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
        return "Invalid month", 400

    #Generate csv with Python instead of shell commands.
    output = io.StringIO(newline="") 
    writer = csv.writer(output)

    #Retrieve database without executing OS commands.
    cursor = db().execute("SELECT * FROM claims")

    writer.writerow([column[0] for column in cursor.description])
    writer.writerows(cursor.fetchall()) # Write database records

    csv_file = BytesIO(output.getvalue().encode("utf-8"))

    return send_file(
        csv_file,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"expenses-{month}.csv")


@app.route("/prefs", methods=["POST"])
def prefs():
    blob = request.form.get("prefs", "")

    # Limit the size of submitted data.
    if len(blob) > 4096:
        return "Data is too large", 400

    try:    #Parse JSON
        data = json.loads(bytes.fromhex(blob).decode("utf-8"))

        if not isinstance(data, dict): #Only takes dictionary preferences
            return "Invalid format", 400
    except (ValueError, UnicodeDecodeError):
        return "Invalid data", 400

    session["prefs"] = data
    return redirect(url_for("index"))


@app.route("/admin/users")
def admin_users():

    if "uid" not in session:  #Checks if the user is logged in
        return redirect(url_for("login"))

    user = db().execute(  #Gets the user role from the database
            "SELECT role FROM users WHERE id = ?",
            (session["uid"],)
        ).fetchone()

    if user is None or user["role"] != "admin":
        abort(403)   #Only administrators can access this page

    rows = db().execute(
        "SELECT id, username, name, role FROM users"
    ).fetchall()

    return render_template("admin.html", users=rows)


@app.route("/debug/config")
def debug_config():
    return {"secret_key": app.secret_key, "db": DB,
            "env": {k: v for k, v in os.environ.items() if "CCT" in k or "FLASK" in k}}

#Introducin Vulnerability CWE-78
def vulnerable_command(user_input):

    return subprocess.run(
        "echo " + user_input,
        shell=True,
        capture_output=True,
        text=True
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
