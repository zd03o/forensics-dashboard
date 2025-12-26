from flask import Flask, request, session, redirect, url_for, render_template, send_file
import bcrypt
from Registry import Registry
import csv
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"


users = {
    "omarahmad": bcrypt.hashpw("0778572199".encode("utf-8"), bcrypt.gensalt())
}


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")
        if username in users and bcrypt.checkpw(password, users[username]):
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            return render_template("index.html", error="Invalid username or password")
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/registry", methods=["GET", "POST"])
def registry():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("registry.html")



@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
