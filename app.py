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

    high_risk = ["appinit", "shell"]
    medium_risk = ["run", "startup"]

    results = []

    if request.method == "POST":
        f = request.files.get("registry_file")
        if f:
            content = f.read().decode(errors="ignore")
            lines = content.splitlines()

            for l in lines:
                ll = l.lower()
                if any(k in ll for k in high_risk):
                    results.append((l, "High"))
                elif any(k in ll for k in medium_risk):
                    results.append((l, "Medium"))

            risk_score = len([r for r in results if r[1] == "High"]) * 2 + \
                         len([r for r in results if r[1] == "Medium"])

            return render_template(
                "registry.html",
                total=len(lines),
                findings=len(results),
                risk=risk_score,
                results=results
            )

    return render_template("registry.html")



@app.route("/logs", methods=["GET", "POST"])
def logs():
    if "user" not in session:
        return redirect(url_for("login"))

    high_risk = [
        "unauthorized",
        "access denied",
        "root",
        "segmentation fault",
        "kernel panic"
    ]

    medium_risk = [
        "failed",
        "error",
        "warning",
        "login failed",
        "invalid"
    ]

    results = []

    if request.method == "POST":
        f = request.files.get("log_file")
        if f:
            content = f.read().decode(errors="ignore")
            lines = content.splitlines()

            for l in lines:
                ll = l.lower()
                if any(k in ll for k in high_risk):
                    results.append((l, "High"))
                elif any(k in ll for k in medium_risk):
                    results.append((l, "Medium"))

            risk_score = (
                len([r for r in results if r[1] == "High"]) * 2 +
                len([r for r in results if r[1] == "Medium"])
            )

            return render_template(
                "logs.html",
                total=len(lines),
                findings=len(results),
                risk=risk_score,
                results=results
            )

    return render_template("logs.html")

@app.route("/tools", methods=["GET", "POST"])
def tools():
    if "user" not in session:
        return redirect(url_for("login"))

    output = None

    if request.method == "POST":
        tool = request.form.get("tool")
        f = request.files.get("file")

        if f:
            content = f.read().decode(errors="ignore")

            if tool == "registry":
                output = registry_tool(content)
            elif tool == "logs":
                output = log_tool(content)

    return render_template("tools.html", output=output)

def registry_tool(content):
    indicators = ["run", "startup", "appinit", "shell"]
    results = []

    for line in content.splitlines():
        if any(i in line.lower() for i in indicators):
            results.append(line)

    return "\n".join(results[:20])


def log_tool(content):
    indicators = ["error", "failed", "unauthorized", "warning"]
    results = []

    for line in content.splitlines():
        if any(i in line.lower() for i in indicators):
            results.append(line)

    return "\n".join(results[:20])

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run()

