#!/usr/bin/env python3
"""
Module app
"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)
auth_service = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def home() -> str:
    """
    Return a simple JSON response
    """
    return jsonify({"message": "Welcome"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def register_user() -> str:
    """ Register a new user """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = auth_service.register_user(email, password)
        if user:
            return jsonify({
                "email": user.email,
                "message": "User successfully created"
            })
    except ValueError:
        return jsonify({
            "message": "Email already registered"
        }), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login_user() -> str:
    """ Create a user session """
    email = request.form.get("email")
    password = request.form.get("password")

    if not auth_service.valid_login(email, password):
        abort(401)

    session_id = auth_service.create_session(email)

    response = jsonify({"email": email, "message": "Successfully logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout_user() -> str:
    """ Terminate the user's session """
    session_id = request.cookies.get("session_id")
    user = auth_service.get_user_from_session_id(session_id)

    if session_id is None or user is None:
        abort(403)

    auth_service.destroy_session(user.id)

    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def get_profile() -> str:
    """ Show the user's profile """
    session_id = request.cookies.get("session_id")
    if session_id is None:
        abort(403)

    user = auth_service.get_user_from_session_id(session_id)
    if user is None:
        abort(403)

    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def request_reset_token() -> str:
    """
    Generate a password reset token for the user
    """
    email = request.form.get('email')
    session_id = auth_service.create_session(email)

    if not session_id:
        abort(403)

    reset_token = auth_service.get_reset_password_token(email)

    return jsonify({"email": email, "reset_token": reset_token})


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def reset_password() -> str:
    """ Reset the user's password """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        auth_service.update_password(reset_token, new_password)
    except Exception:
        abort(403)

    return jsonify({"email": email, "message": "Password updated successfully"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
