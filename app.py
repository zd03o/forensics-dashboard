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

    results = []

    if request.method == "POST":
        f = request.files.get("registry_file")
        if f:

            file_path = "./temp_registry_file"
            f.save(file_path)

            try:
                reg = Registry.Registry(file_path)
                keys_to_check = [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Startup",
                    "System\\CurrentControlSet\\Control\\Session Manager\\AppInit_DLLs"
                ]

                for key_path in keys_to_check:
                    try:
                        key = reg.open(key_path)
                        for value in key.values():
                            results.append({
                                "key": key_path.split("\\")[-1],
                                "name": value.name(),
                                "data": str(value.value()),
                                "risk": "High"
                            })
                    except Registry.RegistryKeyNotFoundException:
                        continue

            except Exception as e:
                return render_template("registry.html", error=f"Error parsing registry: {str(e)}")

           
            session["last_registry_results"] = results

            return render_template(
                "registry.html",
                total=sum(1 for _ in reg.recurse_subkeys()),
                findings=len(results),
                results=results
            )

    return render_template("registry.html")


@app.route("/registry/export")
def export_registry():
    if "user" not in session:
        return redirect(url_for("login"))

    results = session.get("last_registry_results", [])
    if not results:
        return redirect(url_for("registry"))

    filename = "registry_results.csv"

    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["key", "name", "data", "risk"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    return send_file(filename, as_attachment=True)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
