#!/usr/bin/env python3
"""Authentication-related functions and classes.
"""
import bcrypt
from uuid import uuid4
from typing import Union
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _encrypt_password(password: str) -> bytes:
    """Encrypts a password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _create_uuid() -> str:
    """Creates a new UUID.
    """
    return str(uuid4())


class Auth:
    """Handles user authentication operations.
    """

    def __init__(self):
        """Initializes Auth instance and DB connection.
        """
        self._db = DB()

    def register(self, email: str, password: str) -> User:
        """Registers a new user.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _encrypt_password(password))
        raise ValueError("User {} already exists.".format(email))

    def authenticate(self, email: str, password: str) -> bool:
        """Validates a user's credentials.
        """
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return bcrypt.checkpw(
                    password.encode("utf-8"),
                    user.hashed_password,
                )
        except NoResultFound:
            return False
        return False

    def start_session(self, email: str) -> str:
        """Starts a user session.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if user is None:
            return None
        session_id = _create_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_by_session(self, session_id: str) -> Union[User, None]:
        """Retrieves a user by session ID.
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def end_session(self, user_id: int) -> None:
        """Ends the user session.
        """
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def generate_reset_token(self, email: str) -> str:
        """Generates a token for password reset.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError("User not found.")
        reset_token = _create_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def change_password(self, reset_token: str, password: str) -> None:
        """Changes the user's password using the reset token.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token.")
        new_password_hash = _encrypt_password(password)
        self._db.update_user(
            user.id,
            hashed_password=new_password_hash,
            reset_token=None,
        )
