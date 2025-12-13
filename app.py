from flask import Flask, request, session, redirect, url_for, render_template
import bcrypt

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

    suspicious = ["run", "startup", "shell", "appinit"]

    if request.method == "POST":
        f = request.files.get("registry_file")
        if f:
            content = f.read().decode(errors="ignore")
            lines = content.splitlines()

            found = []
            for l in lines:
                for s in suspicious:
                    if s in l.lower():
                        found.append(l)

            return render_template(
                "registry.html",
                total=len(lines),
                suspicious=len(found),
                matches=found[:10]
            )

    return render_template("registry.html")


@app.route("/logs", methods=["GET", "POST"])
def logs():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        f = request.files.get("log_file")
        if f:
            content = f.read().decode(errors="ignore")
            lines = content.splitlines()

            error_count = sum(1 for l in lines if "error" in l.lower())
            warning_count = sum(1 for l in lines if "warning" in l.lower())
            info_count = sum(1 for l in lines if "info" in l.lower())

            sample_errors = [l for l in lines if "error" in l.lower()][:5]

            return render_template(
                "logs.html",
                total=len(lines),
                errors=error_count,
                warnings=warning_count,
                infos=info_count,
                samples=sample_errors
            )

    return render_template("logs.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run()
