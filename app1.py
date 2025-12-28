from flask import Flask, render_template, request
import subprocess
import os
ئء
app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def tools():
    output = None

    if request.method == "POST":
        tool = request.form.get("tool")
        file = request.files.get("file")

        if file:
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)

            try:
                if tool == "registry":
                    result = subprocess.run(
                        ["perl", "tools/regrepper/rip.pl", "-r", file_path],
                        capture_output=True,
                        text=True
                    )

                elif tool == "logs":
                    result = subprocess.run(
                        ["python", "tools/log_analysis.py", file_path],
                        capture_output=True,
                        text=True
                    )

                output = result.stdout

            except Exception as e:
                output = str(e)

    return render_template("tools.html", output=output)

if __name__ == "__main__":
    app.run(port=5001, debug=True)
