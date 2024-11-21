#!/usr/bin/env python3
"""Module for user authentication handling.
"""

import logging
from typing import Union
from uuid import uuid4

import bcrypt
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User

logging.disable(logging.WARNING)


def _encrypt_password(password: str) -> bytes:
    """Encrypts a given password.

    Args:
        password (str): Plain text password.

    Returns:
        bytes: The encrypted password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _create_uuid() -> str:
    """Creates a unique UUID.

    Returns:
        str: The generated UUID.
    """
    return str(uuid4())


class Auth:
    """Handles all authentication-related activities.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user with the provided email and password.

        Args:
            email (str): Email for the new user.
            password (str): Password for the new user.

        Returns:
            User: A User object representing the newly registered user.

        Raises:
            ValueError: If the email is already registered.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass

        hashed_password = _encrypt_password(password)
        user = self._db.add_user(email, hashed_password)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Verifies the user's credentials during login.

        Args:
            email (str): Email of the user.
            password (str): Password of the user.

        Returns:
            bool: True if credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            if user and bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Generates a session for the user.

        Args:
            email (str): The user's email.

        Returns:
            str: The session ID.
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

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieves the user associated with a session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            Union[User, None]: The corresponding user, or None.
        """
        if session_id is None:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Ends a user session.

        Args:
            user_id (int): The user's ID.
        """
        if user_id is None:
            return
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token.

        Args:
            email (str): The email to generate the reset token for.

        Returns:
            str: The reset token.

        Raises:
            ValueError: If the user with the given email doesn't exist.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError()

        reset_token = _create_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password using the reset token.

        Args:
            reset_token (str): The reset token.
            password (str): The new password.

        Raises:
            ValueError: If the reset token is invalid.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")

        new_hashed_password = _encrypt_password(password)
        self._db.update_user(user.id, hashed_password=new_hashed_password, reset_token=None)
