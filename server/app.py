from flask import Flask, request, render_template, redirect, url_for
import base64
import json

app = Flask(__name__)

EVENTS = []  # in-memory store (enough for now)

@app.route("/")
def index():
    return render_template("index.html", events=EVENTS)

@app.route("/api/", methods=["GET"])
def api():
    if not request.query_string:
        return "No data", 400

    try:
        payload = request.query_string.decode()
        raw = base64.b64decode(payload)
        data = json.loads(raw)
        EVENTS.append(data)
        return "OK"
    except Exception as e:
        return str(e), 400

@app.route("/clear")
def clear():
    EVENTS.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
