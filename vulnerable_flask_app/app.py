import os
import subprocess

from flask import Flask, abort, request
from markupsafe import escape

app = Flask(__name__)
# Corrige : secret en dur -> variable d'environnement
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# Corrige Command Injection : liste blanche, aucune entree utilisateur dans un shell
ALLOWED_COMMANDS = {
    "ls": ["ls", "-la"],
    "date": ["date"],
    "uptime": ["uptime"],
}

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Server"] = "webserver"
    return response


@app.route('/')
def index():
    return """
    <h1>Welcome to our vulnerable Flask App!</h1>
    <ul>
        <li><a href="/hello?name=World">Hello Page</a></li>
        <li><a href="/execute?cmd=ls">Execute Command Page</a></li>
        <li><a href="/admin">Admin Area</a></li>
    </ul>
    """


@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    # Corrige XSS : sortie echappee
    return f"""
    <h1>Hello Page</h1>
    <p>Hello, {escape(name)}!</p>
    <p><a href="/">Back to Homepage</a></p>
    """


@app.route('/execute')
def execute():
    command = request.args.get('cmd', 'ls')
    if command not in ALLOWED_COMMANDS:
        allowed = ", ".join(sorted(ALLOWED_COMMANDS))
        return f"""
        <h1>Execute Command Page</h1>
        <p>Command not allowed. Allowed commands: {escape(allowed)}</p>
        <p><a href="/">Back to Homepage</a></p>
        """, 400
    result = subprocess.run(
        ALLOWED_COMMANDS[command],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    # Corrige XSS : toutes les sorties sont echappees
    return f"""
    <h1>Execute Command Page</h1>
    <p>Executing command: <code>{escape(command)}</code></p>
    <pre>{escape(result.stdout)}</pre>
    <pre style="color: red;">{escape(result.stderr)}</pre>
    <p><a href="/">Back to Homepage</a></p>
    """


@app.route('/admin')
def admin():
    token = request.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        abort(403)
    return "<h1>Admin Area</h1>"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
