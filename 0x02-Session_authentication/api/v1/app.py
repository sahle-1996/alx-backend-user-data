#!/usr/bin/env python3
"""API route module."""
import os
from flask import Flask, jsonify, abort, request
from flask_cors import CORS
from api.v1.views import app_views
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_exp_auth import SessionExpAuth
from api.v1.auth.session_db_auth import SessionDBAuth

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Authentication type setup based on environment variable
auth = None
auth_type = os.getenv('AUTH_TYPE', 'auth')
if auth_type == 'auth':
    auth = Auth()
elif auth_type == 'basic_auth':
    auth = BasicAuth()
elif auth_type == 'session_auth':
    auth = SessionAuth()
elif auth_type == 'session_exp_auth':
    auth = SessionExpAuth()
elif auth_type == 'session_db_auth':
    auth = SessionDBAuth()

@app.errorhandler(404)
def handle_404(error) -> str:
    """Handler for 404 errors."""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(401)
def handle_401(error) -> str:
    """Handler for 401 errors."""
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def handle_403(error) -> str:
    """Handler for 403 errors."""
    return jsonify({"error": "Forbidden"}), 403

@app.before_request
def verify_user():
    """Authenticates user prior to handling request."""
    if auth:
        excluded_routes = [
            "/api/v1/status/",
            "/api/v1/unauthorized/",
            "/api/v1/forbidden/",
            "/api/v1/auth_session/login/",
        ]
        if auth.require_auth(request.path, excluded_routes):
            if auth.authorization_header(request) is None and \
                    auth.session_cookie(request) is None:
                abort(401)
            request.current_user = auth.current_user(request)
            if request.current_user is None:
                abort(403)

if __name__ == "__main__":
    app_host = os.getenv("API_HOST", "0.0.0.0")
    app_port = os.getenv("API_PORT", "5000")
    app.run(host=app_host, port=app_port)
