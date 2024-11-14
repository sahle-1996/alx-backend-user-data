#!/usr/bin/env python3
"""Users view module."""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/users', methods=['GET'], strict_slashes=False)
def get_all_users() -> str:
    """GET /api/v1/users
    Return:
      - JSON list of all User objects.
    """
    users = [usr.to_json() for usr in User.all()]
    return jsonify(users)


@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)
def get_user(user_id: str = None) -> str:
    """GET /api/v1/users/:id
    Path parameter:
      - User ID.
    Return:
      - JSON User object.
      - 404 if User ID is invalid.
    """
    if user_id is None:
        abort(404)
    if user_id == 'me':
        if request.current_user is None:
            abort(404)
        return jsonify(request.current_user.to_json())
    usr = User.get(user_id)
    if usr is None:
        abort(404)
    return jsonify(usr.to_json())


@app_views.route('/users/<user_id>', methods=['DELETE'], strict_slashes=False)
def remove_user(user_id: str = None) -> str:
    """DELETE /api/v1/users/:id
    Path parameter:
      - User ID.
    Return:
      - JSON empty if User is deleted.
      - 404 if User ID is invalid.
    """
    if user_id is None:
        abort(404)
    usr = User.get(user_id)
    if usr is None:
        abort(404)
    usr.remove()
    return jsonify({}), 200


@app_views.route('/users', methods=['POST'], strict_slashes=False)
def add_user() -> str:
    """POST /api/v1/users/
    JSON body:
      - email, password.
      - Optional: first_name, last_name.
    Return:
      - JSON User object if created.
      - 400 if User creation fails.
    """
    data = None
    error = None
    try:
        data = request.get_json()
    except Exception:
        data = None
    if data is None:
        error = "Wrong format"
    if error is None and data.get("email", "") == "":
        error = "email missing"
    if error is None and data.get("password", "") == "":
        error = "password missing"
    if error is None:
        try:
            usr = User()
            usr.email = data.get("email")
            usr.password = data.get("password")
            usr.first_name = data.get("first_name")
            usr.last_name = data.get("last_name")
            usr.save()
            return jsonify(usr.to_json()), 201
        except Exception as e:
            error = "Can't create User: {}".format(e)
    return jsonify({'error': error}), 400


@app_views.route('/users/<user_id>', methods=['PUT'], strict_slashes=False)
def modify_user(user_id: str = None) -> str:
    """PUT /api/v1/users/:id
    Path parameter:
      - User ID.
    JSON body:
      - Optional: first_name, last_name.
    Return:
      - JSON User object if updated.
      - 404 if User ID is invalid.
      - 400 if update fails.
    """
    if user_id is None:
        abort(404)
    usr = User.get(user_id)
    if usr is None:
        abort(404)
    data = None
    try:
        data = request.get_json()
    except Exception:
        data = None
    if data is None:
        return jsonify({'error': "Wrong format"}), 400
    if data.get('first_name') is not None:
        usr.first_name = data.get('first_name')
    if data.get('last_name') is not None:
        usr.last_name = data.get('last_name')
    usr.save()
    return jsonify(usr.to_json()), 200
