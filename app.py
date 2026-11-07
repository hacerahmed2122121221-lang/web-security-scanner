import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from scanner import scan_target

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///database.db")

db.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'Completed'
    )
""")

db.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        severity TEXT,
        title TEXT,
        description TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
""")

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target_url = request.form.get("url")
        if not target_url:
            flash("الرجاء إدخال رابط صالح!", "danger")
            return redirect(url_for("index"))
        
        scan_id = db.execute(
            "INSERT INTO scans (url) VALUES (?)", target_url
        )
        
        findings = scan_target(target_url)
        
        for f in findings:
            db.execute(
                "INSERT INTO findings (scan_id, severity, title, description) VALUES (?, ?, ?, ?)",
                scan_id, f["severity"], f["title"], f["description"]
            )
        
        flash("تم تنفيذ الفحص الأمني بنجاح!", "success")
        return redirect(url_for("dashboard", scan_id=scan_id))
        
    return render_template("index.html")

@app.route("/dashboard/<int:scan_id>")
def dashboard(scan_id):
    scans = db.execute("SELECT * FROM scans WHERE id = ?", scan_id)
    if not scans:
        flash("عملية الفحص غير موجودة!", "danger")
        return redirect(url_for("index"))
        
    scan = scans[0]
    findings = db.execute("SELECT * FROM findings WHERE scan_id = ?", scan_id)
    
    return render_template("dashboard.html", scan=scan, findings=findings)

@app.route("/history")
def history():
    scans = db.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    return render_template("history.html", scans=scans)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
