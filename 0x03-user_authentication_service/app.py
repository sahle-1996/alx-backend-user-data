#!/usr/bin/env python3
"""
Main Application Module
"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)
auth_handler = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def home() -> str:
    """
    Provides a welcome message in JSON format.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def register_user() -> str:
    """ Register a new user with email and password """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = auth_handler.register_user(email, password)
        if user:
            return jsonify({
                "email": user.email,
                "message": "user successfully created"
            })
    except ValueError:
        return jsonify({
            "message": "email already in use"
        }), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def create_session() -> str:
    """ Log in and start a session for the user """
    email = request.form.get("email")
    password = request.form.get("password")

    if not auth_handler.valid_login(email, password):
        abort(401)

    session_id = auth_handler.create_session(email)
    response = jsonify({"email": email, "message": "logged in successfully"})
    response.set_cookie("session_id", session_id)
    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def terminate_session() -> str:
    """ Log out the user and destroy their session """
    session_id = request.cookies.get("session_id")
    user = auth_handler.get_user_from_session_id(session_id)

    if not session_id or not user:
        abort(403)

    auth_handler.destroy_session(user.id)
    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def user_profile() -> str:
    """ Display the profile of the logged-in user """
    session_id = request.cookies.get("session_id")
    if not session_id:
        abort(403)

    user = auth_handler.get_user_from_session_id(session_id)
    if not user:
        abort(403)

    return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def request_reset_password() -> str:
    """
    Request a password reset token for a user
    """
    email = request.form.get("email")
    session_id = auth_handler.create_session(email)

    if not session_id:
        abort(403)

    token = auth_handler.get_reset_password_token(email)
    return jsonify({"email": email, "reset_token": token})


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def reset_user_password() -> str:
    """ Update a user's password using a reset token """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    try:
        auth_handler.update_password(reset_token, new_password)
    except Exception:
        abort(403)

    return jsonify({"email": email, "message": "password updated successfully"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
